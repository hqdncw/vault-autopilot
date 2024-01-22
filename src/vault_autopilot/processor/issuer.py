import logging
from dataclasses import dataclass
from typing import Iterable, Union

from .. import dto, state, util
from ..dispatcher import event
from .abstract import ChainBasedProcessor

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
            payload: The payload to create the node from.
            status: An optional status message for the node.

        Returns:
            A new instance of the Node class.
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
class IssuerCheckOrSetProcessor(ChainBasedProcessor[NodeType]):
    state: state.IssuerState

    async def get_upstreams(self, node: NodeType) -> Iterable[NodeType]:
        assert isinstance(node, Node)

        if node.payload.spec.get("chaining"):
            return (
                PlaceholderNode.from_issuer_absolute_path(
                    node.payload.upstream_issuer_absolute_path()
                ),
            )

        return ()

    def register_handlers(self) -> None:
        async def _on_issuer_discovered(ev: event.IssuerDiscovered) -> None:
            await self._schedule(Node.from_payload(ev.payload))

        async def _on_postprocess_requested(_: event.PostProcessRequested) -> None:
            await self._satisfy_remaining_downstreams()

        self.state.observer.register((event.IssuerDiscovered,), _on_issuer_discovered)
        self.state.observer.register(
            (event.PostProcessRequested,), _on_postprocess_requested
        )

    async def _process(self, node: NodeType) -> None:
        assert isinstance(node, Node)

        await self.state.iss_svc.create(node.payload)
        logger.debug("completed processing of issuer %r", node.payload.absolute_path())

        # TODO: Unchanged/Updated events
        await self.state.observer.trigger(event.IssuerCreated(node.payload))
