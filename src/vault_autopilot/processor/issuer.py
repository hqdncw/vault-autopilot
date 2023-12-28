import asyncio
import logging
from dataclasses import dataclass
from itertools import chain
from typing import Union

from .. import dto, state, util
from ..dispatcher import event
from . import abstract

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Node(util.dependency_chain.AbstractNode):
    payload: dto.IssuerCheckOrSetDTO

    def __hash__(self) -> int:
        return hash(self.payload.absolute_path())

    def __repr__(self) -> str:
        return f"Node({self.payload.absolute_path()})"

    @classmethod
    def from_payload(cls, payload: dto.IssuerCheckOrSetDTO) -> "Node":
        """
        Creates a node from given payload.

        Args:
            payload: The payload containing the information to create the node.
            status: The initial status of the node.
        """
        return cls(payload)


@dataclass(slots=True)
class PlaceholderNode(util.dependency_chain.AbstractNode):
    """
    Efficiently represents a :class:`Node` object before its payload is available.

    When working with large datasets, it's often necessary to establish relationships
    between nodes before their payloads are fully loaded. This class allows you to
    create a placeholder node that can be used for ordering dependencies without having
    to wait for the full node information.

    Once a `PlaceholderNode` has been created, it can be used in place of a regular
    `Node` object.

    Args:
        node_hash: A unique identifier for the node that can be used to compare
            equality.

    Example:
        >>> payload = IssuerCheckOrSetDTO(kind="Issuer", spec={"name": "my-issuer",
        ...                                                    "secret_engine": "pki"})
        ...
        ... # Create a placeholder node from an issuer absolute path
        ... placeholder = PlaceholderNode.from_issuer_absolute_path(
        ...     payload.absolute_path())
        ...
        ... assert hash(placeholder) == hash(Node.from_payload(payload))
    """

    node_hash: int

    def __hash__(self) -> int:
        return self.node_hash

    @classmethod
    def from_issuer_absolute_path(cls, path: str) -> "PlaceholderNode":
        """
        Creates a new :class:`PlaceholderNode` instance from an issuer absolute path.

        Args:
            path: The path must be in the format ``pki/my-issuer`` where ``pki`` is the
                PKI engine mount path and ``my-issuer`` is the name of the issuer.
        """
        return cls(hash(path))


NodeType = Union[Node, PlaceholderNode]


@dataclass(slots=True)
class IssuerCheckOrSetProcessor(abstract.AbstractProcessor):
    state: state.IssuerState

    def register_handlers(self) -> None:
        async def _on_issuer_discovered(ev: event.IssuerDiscovered) -> None:
            """
            Responds to the :class:`event.IssuerDiscovered` event by handling newly
            discovered issuers and ensuring they are processed correctly.

            When the payload contains the `chaining` field, check if the upstream issuer
            is already processed. If it is, schedule all known intermediates, including
            the current one, to be processed in the correct order using the established
            dependency chain. If the upstream issuer is not processed, process the
            current intermediate issuer and any other dependents at a later time, when
            the upstream issuer becomes available.

            If the payload does not contain the `chaining` field, process the issuer
            immediately without establishing any dependencies.

            See also:
                :meth:`_process_outstanding_issuers_immediately`
            """
            if ev.payload.spec.get("chaining"):
                async with self.state.dep_chain.lock() as mgr:
                    upstream_hash = hash(ev.payload.upstream_issuer_absolute_path())
                    upstream = mgr.get_node_by_hash(upstream_hash, None)

                    if upstream is None:
                        upstream = PlaceholderNode(node_hash=upstream_hash)
                        mgr.add_node(upstream)

                    intermediate = Node.from_payload(ev.payload)
                    existing_intermediate = mgr.get_node_by_hash(
                        hash(ev.payload.absolute_path()), None
                    )

                    if existing_intermediate is None:
                        mgr.add_node(intermediate)
                    elif isinstance(existing_intermediate, PlaceholderNode):
                        mgr.relabel_nodes(((existing_intermediate, intermediate),))
                    else:
                        raise RuntimeError("Duplicates aren't allowed: %r" % ev.payload)

                    del existing_intermediate

                    mgr.add_edge(upstream, intermediate, "unsatisfied")

                    if not mgr.are_edges_satisfied(upstream):
                        # skip setting up intermediates as the upstream is not yet
                        # available
                        return
            else:
                async with self.state.dep_chain.lock() as mgr:
                    upstream_hash = hash(ev.payload.absolute_path())
                    upstream = mgr.get_node_by_hash(upstream_hash, None)

                    if upstream is None:
                        upstream = PlaceholderNode(node_hash=upstream_hash)
                        mgr.add_node(upstream)

                await self._process(ev.payload)

            await self._fulfill_unsatisfied_intermediates(upstream)

        async def _on_postprocess_requested(_: event.PostProcessRequested) -> None:
            """
            Responds to the :class:`event.PostProcessRequested` event by processing any
            unsatisfied issuer nodes.

            Args:
                _: The event triggered by the dispatcher when post-processing is
                    requested.
            """
            await self._process_outstanding_issuers_immediately()

        self.state.observer.register((event.IssuerDiscovered,), _on_issuer_discovered)
        self.state.observer.register(
            (event.PostProcessRequested,), _on_postprocess_requested
        )

    async def _process(self, payload: dto.IssuerCheckOrSetDTO) -> None:
        """Processes the given payload."""
        await self.state.iss_svc.create(payload)
        # TODO: Unchanged/Updated events
        await self.state.observer.trigger(event.IssuerCreated(payload))

    async def _fulfill_unsatisfied_intermediates(self, upstream: NodeType) -> None:
        logger.debug("fulfilling intermediates for upstream: %r", hash(upstream))
        async with self.state.dep_chain.lock() as mgr:
            for intermediate in (
                unsatisfied_intermediates := tuple(mgr.find_unsatisfied_nodes(upstream))
            ):
                mgr.update_edge_status(upstream, intermediate, status="in_process")

        async with asyncio.TaskGroup() as tg:
            for intermediate in unsatisfied_intermediates:
                assert isinstance(intermediate, Node)
                logger.debug("creating task for intermediate %r", hash(intermediate))
                await util.coro.create_task_limited(
                    tg, self.state.sem, self._process(intermediate.payload)
                )

        if not unsatisfied_intermediates:
            logger.debug("no outbound edges were found for node %r", hash(upstream))
            return

        async with self.state.dep_chain.lock() as mgr:
            for intermediate in unsatisfied_intermediates:
                mgr.update_edge_status(upstream, intermediate, status="satisfied")

            # Optimize memory usage by replacing nodes with payloads with placeholder
            # nodes. Since the issuer has been processed, we no longer need to store the
            # payload data in the node.
            mgr.relabel_nodes(
                chain(
                    (
                        (
                            upstream,
                            PlaceholderNode.from_issuer_absolute_path(
                                upstream.payload.absolute_path()
                            ),
                        ),
                    )
                    if isinstance(upstream, Node)
                    else (),
                    (
                        (
                            intermediate,
                            PlaceholderNode.from_issuer_absolute_path(
                                intermediate.payload.absolute_path()
                            ),
                        )
                        for intermediate in unsatisfied_intermediates
                        if isinstance(intermediate, Node)
                    ),
                )
            )

        for intermediate in unsatisfied_intermediates:
            await self._fulfill_unsatisfied_intermediates(intermediate)

    async def _process_outstanding_issuers_immediately(self) -> None:
        """
        Processes issuers for which the upstream has not yet been processed.
        """
        async with self.state.dep_chain.lock() as mgr:
            for upstream, intmd in (edges := tuple(mgr.find_all_unsatisfied_edges())):
                mgr.update_edge_status(upstream, intmd, status="in_process")

        async with asyncio.TaskGroup() as tg:
            for _, intmd in edges:
                if not isinstance(intmd, Node):
                    logger.debug(
                        "Unable to force the node to be processed as it has no payload."
                    )
                    continue

                logger.debug("forcing processing of node: %r", hash(intmd))
                await util.coro.create_task_limited(
                    tg, util.coro.BoundlessSemaphore(), self._process(intmd.payload)
                )
