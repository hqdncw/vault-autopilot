import logging
from dataclasses import dataclass
from typing import Iterable, Union

from .. import dto, state
from ..dispatcher import event
from ..util.dependency_chain import AbstractNode
from .abstract import ChainBasedProcessor
from .issuer import PlaceholderNode as IssuerNode

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PKIRoleNode(AbstractNode):
    payload: dto.PKIRoleCheckOrSetDTO

    def __hash__(self) -> int:
        return hash(self.payload.absolute_path())

    @classmethod
    def from_payload(cls, payload: dto.PKIRoleCheckOrSetDTO) -> "PKIRoleNode":
        return cls(payload)


@dataclass(slots=True)
class PKIRolePlaceholderNode(AbstractNode):
    node_hash: int

    def __hash__(self) -> int:
        return self.node_hash

    @classmethod
    def from_pki_role_absolute_path(cls, path: str) -> "PKIRolePlaceholderNode":
        """
        Creates a new :class:`PKIRolePlaceholderNode` instance from a PKI Role absolute
        path.

        Args:
            path: The path must be in the format ``pki/my-role`` where ``pki`` is the
                PKI engine mount path and ``my-role`` is the name of the role.
        """
        return cls(hash(path))


NodeType = Union[PKIRoleNode, IssuerNode]


@dataclass(slots=True)
class PKIRoleCheckOrSetProcessor(ChainBasedProcessor[NodeType]):
    state: state.PKIRoleState

    async def get_upstreams(self, node: NodeType) -> Iterable[NodeType]:
        assert isinstance(node, PKIRoleNode)

        return (
            IssuerNode.from_issuer_absolute_path(
                node.payload.issuer_ref_absolute_path()
            ),
        )

    def register_handlers(self) -> None:
        async def _on_pki_role_discovered(
            ev: event.PKIRoleDiscovered,
        ) -> None:
            await self._schedule(PKIRoleNode.from_payload(ev.payload))

        async def _on_issuer_processed(ev: event.IssuerProcessed) -> None:
            async with self.state.dep_chain.lock() as mgr:
                issuer_node = IssuerNode.from_issuer_absolute_path(
                    ev.payload.absolute_path()
                )
                if not mgr.has_node(issuer_node):
                    mgr.add_node(issuer_node)

            await self._satisfy_downstreams(
                IssuerNode.from_issuer_absolute_path(ev.payload.absolute_path())
            )

        async def _on_postprocess_requested(_: event.PostProcessRequested) -> None:
            await self._satisfy_remaining_downstreams()

        self.state.observer.register(
            (event.PKIRoleDiscovered,), _on_pki_role_discovered
        )
        self.state.observer.register(
            (event.IssuerCreated, event.IssuerUpdated, event.IssuerUnchanged),
            _on_issuer_processed,
        )
        self.state.observer.register(
            (event.PostProcessRequested,), _on_postprocess_requested
        )

    async def _process(self, node: NodeType) -> None:
        assert isinstance(node, PKIRoleNode)

        await self.state.pki_role_svc.create_or_update(node.payload)
        logger.debug(
            "completed processing of PKI Role %r", node.payload.absolute_path()
        )

        await self.state.observer.trigger(event.PKIRoleCreated(node.payload))
