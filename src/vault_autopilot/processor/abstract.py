import abc
import logging
from asyncio import Semaphore, TaskGroup
from dataclasses import dataclass
from itertools import groupby
from typing import Generic, Iterable, TypeVar

from ironfence import Mutex

from ..util.coro import create_task_limited
from ..util.dependency_chain import DependencyChain

T = TypeVar("T")

logger = logging.getLogger(__name__)


class AbstractProcessor(abc.ABC):
    @abc.abstractmethod
    def register_handlers(self) -> None:
        ...


@dataclass(kw_only=True)
class ChainBasedProcessorState(Generic[T]):
    sem: Semaphore
    dep_chain: Mutex[DependencyChain[T]]


@dataclass(slots=True)
class ChainBasedProcessor(AbstractProcessor, Generic[T]):
    state: ChainBasedProcessorState[T]

    @abc.abstractmethod
    async def build_upstreams(self, node: T) -> Iterable[T]:
        """
        Return an iterable of upstream nodes for the given node.

        An upstream node is a node that has an incoming edge to the given node. In other
        words, it is a node that is reachable from the given node by following an
        incoming edge.

        References:
            https://www.researchgate.net/figure/Upstream-and-downstream-nodes-in-a-topology_fig2_263090402

        Args:
            node: The node for which to find the upstream nodes.

        Returns:
            An iterable of upstream nodes. May be empty.
        """

    @abc.abstractmethod
    async def _process(self, node: T) -> None:
        ...

    async def _schedule(self, node: T) -> None:
        if upstream_list := await self.build_upstreams(node):
            async with self.state.dep_chain.lock() as mgr:
                for upstream in upstream_list:
                    mgr.add_edge(upstream, node, "unsatisfied")

            if mgr.are_inbound_edges_satisfied(node, default=False) is not True:
                return

            # Process node immediately due to satisfied upstream edges.
            await self._process(node)

            async with self.state.dep_chain.lock() as mgr:
                for upstream in upstream_list:
                    mgr.update_edge_status(upstream, node, status="satisfied")
        else:
            # No upstreams means the node's ready for immediate processing.
            async with self.state.dep_chain.lock() as mgr:
                mgr.add_node(node)

            await self._process(node)

        await self.satisfy_outbound_edges_for(node)

        # TODO: call relabel_nodes() to reduce memory consumption.

    async def satisfy_outbound_edges_for(self, node: T) -> None:
        logger.debug(
            "[%s] satisfying outbound edges for node %r",
            self.__class__.__name__,
            hash(node),
        )

        async with self.state.dep_chain.lock() as mgr:
            for downstream in (
                downstream_list := tuple(mgr.filter_nodes_for_satisfaction(node))
            ):
                mgr.update_edge_status(node, downstream, status="in_process")

        if downstream_list:
            async with TaskGroup() as tg:
                for downstream in downstream_list:
                    await self._create_task(tg, downstream)
        else:
            logger.debug(
                "[%s] no outbound edges were found for node %r",
                self.__class__.__name__,
                hash(node),
            )

        async with self.state.dep_chain.lock() as mgr:
            for downstream in downstream_list:
                mgr.update_edge_status(node, downstream, status="satisfied")

        for downstream in downstream_list:
            await self.satisfy_outbound_edges_for(downstream)

    async def satisfy_any_downstreams(self) -> None:
        logger.debug("[%s] satisfying any outbound edges", self.__class__.__name__)

        async with self.state.dep_chain.lock() as mgr:
            edges = tuple(mgr.find_all_unsatisfied_edges())

            for upstream, downstream in edges:
                mgr.update_edge_status(upstream, downstream, status="in_process")

        async with TaskGroup() as tg:
            for upstream, edge_batch in groupby(edges, key=lambda t: t[0]):
                for edge in edge_batch:
                    logger.debug("trying to satisfy edge %r", hash(edge))
                    await self._create_task(tg, edge[1])

        async with self.state.dep_chain.lock() as mgr:
            for upstream, downstream in edges:
                mgr.update_edge_status(upstream, downstream, status="satisfied")

    async def _create_task(self, tg: TaskGroup, node: T) -> None:
        logger.debug(
            "[%s] create a task for a node %r", self.__class__.__name__, hash(node)
        )
        await create_task_limited(tg, self.state.sem, self._process(node))
