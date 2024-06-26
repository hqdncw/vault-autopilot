import logging
from abc import ABC, abstractmethod
from asyncio import Semaphore, TaskGroup
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Generic, Iterable, Self, TypeVar

from ironfence import Mutex
from typing_extensions import TYPE_CHECKING, override

from vault_autopilot.exc import UnresolvedDependencyError

from .._pkg import asyva
from ..util.coro import create_task_limited
from ..util.dependency_chain import AbstractNode as Node
from ..util.dependency_chain import DependencyChain, FallbackNode

if TYPE_CHECKING:
    from ..dispatcher import event

T = TypeVar("T", bound="AbstractNode | AbstractFallbackNode")
P = TypeVar("P")

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AbstractNode(Node):
    absolute_path: str


@dataclass(slots=True)
class AbstractFallbackNode(FallbackNode):
    absolute_path: str

    @classmethod
    def from_absolute_path(cls, path: str) -> Self:
        return cls(node_hash=hash(path), absolute_path=path)

    @override
    def __hash__(self) -> int:
        return self.node_hash


@dataclass(slots=True)
class SecretsEngineFallbackNode(AbstractFallbackNode):
    @override
    def __hash__(self) -> int:
        return self.node_hash


@dataclass(slots=True)
class AbstractProcessor(ABC, Generic[P]):
    client: asyva.Client
    observer: "event.EventObserver[P]"
    sem: Semaphore

    @abstractmethod
    def initialize(self) -> None: ...


@dataclass(slots=True)
class ChainBasedProcessor(AbstractProcessor[P], Generic[T, P]):
    dep_chain: Mutex[DependencyChain[T]]
    shutdown_event: type[P]

    @abstractmethod
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

    @abstractmethod
    async def _flush(self, node: T) -> None: ...

    @property
    @abstractmethod
    def upstream_dependency_triggers(self) -> Sequence[type[P]]: ...

    @abstractmethod
    def upstream_node_builder(self, ev: P) -> T: ...

    @abstractmethod
    def downstream_selector(self, node: T) -> bool: ...

    @override
    def initialize(self) -> None:
        async def _on_trigger(ev: P) -> None:
            upstream, downstreams_to_flush = self.upstream_node_builder(ev), []

            async with self.dep_chain.lock() as mgr:
                if not mgr.has_node(upstream):
                    mgr.add_node(upstream)
                    mgr.set_node_status(upstream, "satisfied")
                    return

                mgr.set_node_status(upstream, "satisfied")

                for downstream in (
                    n
                    for n in mgr.filter_downstreams(upstream, self.downstream_selector)
                    if mgr.are_upstreams_satisfied(n)
                    and mgr.get_node_status(n) == "pending"
                ):
                    downstreams_to_flush.append(downstream)
                    mgr.set_node_status(downstream, status="in_progress")

            await self.flush_nodes(downstreams_to_flush)

        self.observer.register(
            self.upstream_dependency_triggers,
            _on_trigger,
        )
        self.observer.register((self.shutdown_event,), self._on_shutdown_requested)

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
                        logger.debug(
                            "[%s] add node %r", self.__class__.__name__, upstream
                        )
                        mgr.add_node(upstream)

                    mgr.add_edge(upstream, node)

            if not mgr.are_upstreams_satisfied(node):
                return
        else:
            async with self.dep_chain.lock() as mgr:
                _ = mgr.add_node(node)

        await self.flush_nodes((node,))

        # TODO: replace flushed nodes by fallback nodes to reduce memory consumption.

    async def flush_pending_downstreams_for(self, node: T) -> None:
        """
        Flushes the pending downstreams of a given node in the dependency chain.

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
                        function=lambda nbr: mgr.get_node_status(nbr) == "pending"
                        and mgr.are_upstreams_satisfied(nbr),
                    )
                )
            ):
                mgr.set_node_status(downstream, status="in_progress")

        if downstream_bunch:
            await self.flush_nodes(downstream_bunch)
        else:
            logger.debug(
                "[%s] no pending downstreams were found for node %r, flushing aborted",
                self.__class__.__name__,
                hash(node),
            )

    async def flush_nodes(self, node_bunch: Sequence[T]) -> None:
        async with TaskGroup() as tg:
            for node in node_bunch:
                logger.debug("creating task for flushing node %s", node)
                await create_task_limited(tg, self.sem, self._flush(node))

        async with self.dep_chain.lock() as mgr:
            for node in node_bunch:
                mgr.set_node_status(node, status="satisfied")

        async with TaskGroup() as tg:
            for node in node_bunch:
                await create_task_limited(
                    tg, self.sem, self.flush_pending_downstreams_for(node)
                )

    async def _on_shutdown_requested(self, _: P) -> None:
        async with self.dep_chain.lock() as mgr:
            unresolved_deps = tuple(mgr.get_pending_edges())

        from ..dispatcher.event import UnresolvedDepsDetected

        if unresolved_deps:
            await self.observer.trigger(
                UnresolvedDepsDetected(  # type: ignore[reportArgumentType]
                    tuple(
                        map(
                            lambda edge: UnresolvedDependencyError(
                                "{ctx[resource_ref]!r} references undefined "
                                "{ctx[dependency_ref]!r}",
                                ctx=UnresolvedDependencyError.Context(
                                    resource_ref=edge[1].absolute_path,
                                    dependency_ref=edge[0].absolute_path,
                                ),
                            ),
                            unresolved_deps,
                        )
                    )
                )
            )
