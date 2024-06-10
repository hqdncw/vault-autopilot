import logging
from collections.abc import Iterable
from dataclasses import dataclass

from typing_extensions import override

from .. import dto
from ..dispatcher import event
from ..service import PKIRoleService
from ..util.dependency_chain import AbstractNode
from .abstract import ChainBasedProcessor, SecretsEngineFallbackNode
from .issuer import IssuerFallbackNode

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

    @override
    def __hash__(self) -> int:
        return hash(self.payload.absolute_path())

    @classmethod
    def from_payload(cls, payload: dto.PKIRoleApplyDTO) -> "PKIRoleNode":
        return cls(payload)


NodeType = PKIRoleNode | IssuerFallbackNode | SecretsEngineFallbackNode


@dataclass(slots=True)
class PKIRoleApplyProcessor(
    ChainBasedProcessor[NodeType, event.EventObserver[event.EventType]]
):
    pki_role_svc: PKIRoleService

    @override
    async def _build_fallback_upstream_nodes(
        self, node: NodeType
    ) -> Iterable[NodeType]:
        assert isinstance(node, PKIRoleNode)

        return (
            IssuerFallbackNode.from_issuer_absolute_path(
                node.payload.issuer_ref_absolute_path()
            ),
            SecretsEngineFallbackNode.from_absolute_path(
                node.payload.spec["secrets_engine"]
            ),
        )

    @override
    def initialize(self) -> None:
        async def _on_pki_role_apply_requested(
            ev: event.PKIRoleApplicationRequested,
        ) -> None:
            await self.schedule(PKIRoleNode.from_payload(ev.resource))

        async def _on_issuer_processed(ev: event.IssuerApplySuccess) -> None:
            async with self.dep_chain.lock() as mgr:
                issuer_node = IssuerFallbackNode.from_issuer_absolute_path(
                    ev.resource.absolute_path()
                )
                if not mgr.has_node(issuer_node):
                    _ = mgr.add_node(issuer_node)

            await self.flush_pending_downstreams_for(
                IssuerFallbackNode.from_issuer_absolute_path(
                    ev.resource.absolute_path()
                )
            )

        async def _on_postprocess_requested(_: event.ShutdownRequested) -> None:
            await self.flush_any_pending_downstreams()

        self.observer.register(
            (event.PKIRoleApplicationRequested,), _on_pki_role_apply_requested
        )
        self.observer.register(
            (
                event.IssuerVerifySuccess,
                event.IssuerUpdateSuccess,
                event.IssuerCreateSuccess,
            ),
            _on_issuer_processed,
        )
        self.observer.register((event.ShutdownRequested,), _on_postprocess_requested)

    @override
    async def _flush(self, node: NodeType) -> None:
        assert isinstance(node, PKIRoleNode)

        await self.observer.trigger(event.PKIRoleApplicationInitiated(node.payload))

        # TODO: VerifySuccess, VerifyError, UpdateSuccess, UpdateError
        try:
            await self.pki_role_svc.update_or_create(node.payload)
        except Exception:
            await self.observer.trigger(event.PKIRoleCreateError(node.payload))
            raise

        logger.debug("applying finished %r", node.payload.absolute_path())

        await self.observer.trigger(event.PKIRoleCreateSuccess(node.payload))
