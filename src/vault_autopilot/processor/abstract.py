import abc
import logging
from asyncio import Semaphore, TaskGroup
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import groupby
from typing import Generic, Iterable, TypeVar

from ironfence import Mutex
from typing_extensions import override

from .._pkg import asyva
from ..util.coro import create_task_limited
from ..util.dependency_chain import DependencyChain, FallbackNode

T = TypeVar("T")
P = TypeVar("P")

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SecretsEngineFallbackNode(FallbackNode):
    @classmethod
    def from_absolute_path(cls, path: str) -> "SecretsEngineFallbackNode":
        return cls(node_hash=hash(path))

    @override
    def __hash__(self) -> int:
        return self.node_hash


@dataclass(slots=True)
class AbstractProcessor(abc.ABC, Generic[T]):
    client: asyva.Client
    observer: T
    sem: Semaphore

    @abc.abstractmethod
    def initialize(self) -> None: ...


@dataclass(slots=True)
class ChainBasedProcessor(AbstractProcessor[P], Generic[T, P]):
    dep_chain: Mutex[DependencyChain[T]]

    @abc.abstractmethod
    async def _build_fallback_upstream_nodes(self, node: T) -> Iterable[T]:
        """
        Build fallback upstream nodes for a given node.

        In a chain-based system, nodes rely on each other for input or processing. If a
        node's primary upstream node fails or becomes unavailable, the system needs to
        switch to a fallback upstream node to keep working. The
        `_build_fallback_upstream_nodes` method finds and returns these fallback nodes.

        Additionally, this method can help manage memory use by replacing processed
        nodes with lightweight fallback nodes that don't have the original data. This
        optimizes the system's memory usage and improves performance.

        Note:
            An upstream node is a node that has an outgoing edge to the given node. In
            other words, it is a node that is reachable from the given node by following
            an incoming edge.

        References:
            https://www.researchgate.net/figure/Upstream-and-downstream-nodes-in-a-topology_fig2_263090402

        Args:
            node: The node for which to build the fallback upstream nodes.

        Returns:
            An iterable of fallback upstream nodes. May be empty.
        """

    @abc.abstractmethod
    async def _flush(self, node: T) -> None: ...

    async def schedule(self, node: T) -> None:
        """
        Schedule a node for flushing and manage its dependencies.

        This method schedules a node for flushing, ensuring that all its upstream
        dependencies are satisfied before flushing. If the node has no upstream
        dependencies, it is directly scheduled for flushing.

        Warning:
            This method does not guarantee immediate flushing of the node. The actual
            flushing may occur at a later time, depending on the satisfaction of
            dependencies.

        Args:
            node: The node to be scheduled.

        Returns:
            None
        """
        if upstream_fbs := await self._build_fallback_upstream_nodes(node):
            async with self.dep_chain.lock() as mgr:
                mgr.add_node(node)

                for upstream in upstream_fbs:
                    if not mgr.has_node(upstream):
                        mgr.add_node(upstream)

                    mgr.add_edge(upstream, node, "pending")

            if not mgr.are_inbound_edges_satisfied(node):
                return

            await self._flush(node)

            async with self.dep_chain.lock() as mgr:
                for upstream in upstream_fbs:
                    mgr.update_edge_status(upstream, node, status="satisfied")
        else:
            async with self.dep_chain.lock() as mgr:
                _ = mgr.add_node(node)

            await self._flush(node)

        await self.flush_pending_downstreams_for(node)

        # TODO: replace flushed nodes by fallback nodes to reduce memory consumption.

    async def flush_pending_downstreams_for(self, node: T) -> None:
        """
        Flushes the pending downstreams of a given node in the dependency chain.

        Warning:
            This method only flushes downstreams that have all their edges with status
            'satisfied', except for the edge coming from the given node.

        Args:
            node: The node whose downstreams are to be flushed.

        Returns:
            None
        """
        logger.debug(
            "[%s] flushing pending downstreams for upstream %r",
            self.__class__.__name__,
            hash(node),
        )

        async with self.dep_chain.lock() as mgr:
            for downstream in (
                downstream_bunch := tuple(
                    mgr.filter_downstreams(
                        node,
                        function=lambda nbr: mgr.get_edge_status(node, nbr)
                        != "satisfied"
                        and mgr.are_inbound_edges_satisfied(
                            nbr,
                            exclude=lambda edge: edge[0] == hash(node),
                        ),
                    )
                )
            ):
                mgr.update_edge_status(node, downstream, status="in_progress")

        if downstream_bunch:
            await self.flush_downstreams(node, downstream_bunch)
        else:
            logger.debug(
                "[%s] no pending downstreams were found for node %r, flushing aborted",
                self.__class__.__name__,
                hash(node),
            )

    async def flush_downstreams(
        self, upstream: T, downstream_bunch: Sequence[T]
    ) -> None:
        async with TaskGroup() as tg:
            for downstream in downstream_bunch:
                await self._flush_limited(tg, downstream)

        async with self.dep_chain.lock() as mgr:
            for downstream in downstream_bunch:
                for upstream in mgr.filter_upstreams(downstream, lambda _: True):
                    mgr.update_edge_status(upstream, downstream, status="satisfied")

        for downstream in downstream_bunch:
            await self.flush_pending_downstreams_for(downstream)

    async def flush_any_pending_downstreams(self) -> None:
        """Flushes any pending downstreams in the dependency chain."""

        logger.debug("[%s] flushing any pending downstreams", self.__class__.__name__)

        async with self.dep_chain.lock() as mgr:
            edges = tuple(mgr.get_pending_edges())

            for upstream, downstream in edges:
                mgr.update_edge_status(upstream, downstream, status="in_progress")

        async with TaskGroup() as tg:
            for upstream, edge_batch in groupby(edges, key=lambda t: t[0]):
                for edge in edge_batch:
                    logger.debug("flushing downstream %r", edge)
                    await self._flush_limited(tg, edge[1])

        async with self.dep_chain.lock() as mgr:
            for upstream, downstream in edges:
                mgr.update_edge_status(upstream, downstream, status="satisfied")

    async def _flush_limited(self, tg: TaskGroup, node: T) -> None:
        logger.debug("creating task for flushing node %s", node)
        await create_task_limited(tg, self.sem, self._flush(node))
