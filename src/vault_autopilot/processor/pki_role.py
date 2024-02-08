import logging
from dataclasses import dataclass
from typing import Iterable, Union

from .. import dto, state
from ..dispatcher import event
from ..util.dependency_chain import AbstractNode
from .abstract import ChainBasedProcessor
from .issuer import PlaceholderNode as IssuerNode

logger = logging.getLogger(__name__)


# APPLY_STATUS_EVENT_MAP: dict[
#     ApplyResultStatus, Type[Union[event.PKIRoleApplySuccess, event.PKIRoleApplyError]]
# ] = {
#     "verify_success": event.PKIRoleVerifySuccess,
#     "create_success": event.PKIRoleCreateSuccess,
#     "update_success": event.PKIRoleUpdateSuccess,
#     "verify_error": event.PKIRoleVerifyError,
#     "create_error": event.PKIRoleCreateError,
#     "update_error": event.PKIRoleUpdateError,
# }


@dataclass(slots=True)
class PKIRoleNode(AbstractNode):
    payload: dto.PKIRoleApplyDTO

    def __hash__(self) -> int:
        return hash(self.payload.absolute_path())

    @classmethod
    def from_payload(cls, payload: dto.PKIRoleApplyDTO) -> "PKIRoleNode":
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
class PKIRoleApplyProcessor(ChainBasedProcessor[NodeType]):
    state: state.PKIRoleState

    async def build_upstreams(self, node: NodeType) -> Iterable[NodeType]:
        assert isinstance(node, PKIRoleNode)

        return (
            IssuerNode.from_issuer_absolute_path(
                node.payload.issuer_ref_absolute_path()
            ),
        )

    def register_handlers(self) -> None:
        async def _on_pki_role_apply_requested(ev: event.PKIRoleApplyRequested) -> None:
            await self._schedule(PKIRoleNode.from_payload(ev.resource))

        async def _on_issuer_processed(ev: event.IssuerApplySuccess) -> None:
            async with self.state.dep_chain.lock() as mgr:
                issuer_node = IssuerNode.from_issuer_absolute_path(
                    ev.resource.absolute_path()
                )
                if not mgr.has_node(issuer_node):
                    mgr.add_node(issuer_node)

            await self.satisfy_outbound_edges_for(
                IssuerNode.from_issuer_absolute_path(ev.resource.absolute_path())
            )

        async def _on_postprocess_requested(_: event.PostProcessRequested) -> None:
            await self.satisfy_any_downstreams()

        self.state.observer.register(
            (event.PKIRoleApplyRequested,), _on_pki_role_apply_requested
        )
        self.state.observer.register(
            (
                event.IssuerVerifySuccess,
                event.IssuerUpdateSuccess,
                event.IssuerCreateSuccess,
            ),
            _on_issuer_processed,
        )
        self.state.observer.register(
            (event.PostProcessRequested,), _on_postprocess_requested
        )

    async def _process(self, node: NodeType) -> None:
        assert isinstance(node, PKIRoleNode)

        await self.state.observer.trigger(event.PKIRoleApplyStarted(node.payload))

        # TODO: VerifySuccess, VerifyError, UpdateSuccess, UpdateError
        try:
            await self.state.pki_role_svc.update_or_create(node.payload)
        except Exception:
            await self.state.observer.trigger(event.PKIRoleCreateError(node.payload))
            raise

        await self.state.observer.trigger(event.PKIRoleCreateSuccess(node.payload))

        logger.debug(
            "pki role resource applying finished: %r", node.payload.absolute_path()
        )
