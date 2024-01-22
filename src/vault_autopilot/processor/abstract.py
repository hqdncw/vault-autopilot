import abc
import logging
from asyncio import Semaphore, TaskGroup
from dataclasses import dataclass
from itertools import groupby
from typing import Any, Coroutine, Generic, Iterable, TypeVar

from ironfence import Mutex

from ..util.coro import create_task_limited
from ..util.dependency_chain import DependencyChain

T = TypeVar("T")

logger = logging.getLogger(__name__)


class AbstractProcessor(abc.ABC):
    @abc.abstractmethod
    def register_handlers(self) -> None:
        ...


@dataclass(slots=True)
class ChainBasedProcessorState(Generic[T]):
    sem: Semaphore
    dep_chain: Mutex[DependencyChain[T]]


@dataclass(slots=True)
class ChainBasedProcessor(AbstractProcessor, Generic[T]):
    state: ChainBasedProcessorState[T]

    @abc.abstractmethod
    async def get_upstreams(self, node: T) -> Iterable[T]:
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
    def _process(self, node: T) -> Coroutine[Any, Any, Any]:
        ...

    async def _schedule(self, node: T) -> None:
        if upstream_list := await self.get_upstreams(node):
            async with self.state.dep_chain.lock() as mgr:
                for upstream in upstream_list:
                    mgr.add_edge(upstream, node, "unsatisfied")

            if mgr.are_inbound_edges_satisfied(node, default=False) is True:
                # process the node immediately as all its inbound edges are satisfied
                await self._process(node)
            else:
                return

            async with self.state.dep_chain.lock() as mgr:
                for upstream in upstream_list:
                    mgr.update_edge_status(upstream, node, status="satisfied")
        else:
            # the node can not have inbound edges so we can process it immediately
            async with self.state.dep_chain.lock() as mgr:
                mgr.add_node(node)

            await self._process(node)

        await self._satisfy_downstreams(node)

        # TODO: call relabel_nodes() to reduce memory consumption.

    async def _satisfy_downstreams(self, upstream: T) -> None:
        logger.debug(
            "satisfying all registered downstream nodes for upstream %r", hash(upstream)
        )

        async with self.state.dep_chain.lock() as mgr:
            for downstream in (
                downstream_list := tuple(mgr.filter_nodes_for_satisfaction(upstream))
            ):
                mgr.update_edge_status(upstream, downstream, status="in_process")

        if downstream_list:
            async with TaskGroup() as tg:
                for downstream in downstream_list:
                    await self._create_task(tg, downstream)
        else:
            logger.debug("no downstreams were found for upstream %r", hash(upstream))

        async with self.state.dep_chain.lock() as mgr:
            for downstream in downstream_list:
                mgr.update_edge_status(upstream, downstream, status="satisfied")

        for upstream in downstream_list:
            await self._satisfy_downstreams(upstream)

    async def _satisfy_remaining_downstreams(self) -> None:
        logger.debug(
            "satisfying any remaining downstream nodes that have not been satisfied "
            "yet."
        )

        async with self.state.dep_chain.lock() as mgr:
            edges = tuple(mgr.find_all_unsatisfied_edges())

            for policy, pwd in edges:
                mgr.update_edge_status(policy, pwd, status="in_process")

        async with TaskGroup() as tg:
            for policy, node_batch in groupby(edges, key=lambda t: t[0]):
                for edge in node_batch:
                    logger.debug(
                        "processing downstream node %r forced without resolving "
                        "its upstream",
                        hash(edge[1]),
                    )
                    await self._create_task(tg, edge[1])

        async with self.state.dep_chain.lock() as mgr:
            for policy, pwd in edges:
                mgr.update_edge_status(policy, pwd, status="satisfied")

    async def _create_task(self, tg: TaskGroup, node: T) -> None:
        logger.debug("creating a processing task for a node %r", hash(node))
        await create_task_limited(tg, self.state.sem, self._process(node))
