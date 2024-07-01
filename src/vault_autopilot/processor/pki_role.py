import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Sequence

from typing_extensions import override

from vault_autopilot.service.abstract import ApplyResult

from .. import dto
from ..dispatcher import event
from ..service import PKIRoleService
from .abstract import AbstractNode, ChainBasedProcessor
from .issuer import IssuerFallbackNode

logger = logging.getLogger(__name__)


NODE_PREFIX = "pki-roles/"


@dataclass(slots=True)
class PKIRoleNode(AbstractNode):
    payload: dto.PKIRoleApplyDTO

    @override
    def __hash__(self) -> int:
        return hash(NODE_PREFIX + self.absolute_path)

    @classmethod
    def from_payload(cls, payload: dto.PKIRoleApplyDTO) -> "PKIRoleNode":
        return cls(payload.absolute_path(), payload)


NodeType = PKIRoleNode | IssuerFallbackNode


@dataclass(slots=True)
class PKIRoleApplyProcessor(
    ChainBasedProcessor[NodeType, event.EventType],
):
    pki_role_svc: PKIRoleService

    @override
    async def _build_fallback_upstream_nodes(
        self, node: NodeType
    ) -> Iterable[NodeType]:
        assert isinstance(node, PKIRoleNode), node

        return (IssuerFallbackNode(node.payload.spec["role"]["issuer_ref"]),)

    @override
    def initialize(self) -> None:
        async def _on_pki_role_apply_requested(
            ev: event.PKIRoleApplicationRequested,
        ) -> None:
            await self.schedule(PKIRoleNode.from_payload(ev.resource))

        self.observer.register(
            (event.PKIRoleApplicationRequested,), _on_pki_role_apply_requested
        )

        ChainBasedProcessor.initialize(self)

    @property
    def upstream_dependency_triggers(
        self,
    ) -> Sequence[type[event.IssuerApplySuccess]]:
        return (
            event.IssuerVerifySuccess,
            event.IssuerUpdateSuccess,
            event.IssuerCreateSuccess,
        )

    @override
    def upstream_node_builder(self, ev: event.EventType) -> NodeType:
        assert isinstance(ev, event.IssuerApplySuccess), ev
        return IssuerFallbackNode(ev.resource.absolute_path())

    @override
    def downstream_selector(self, node: NodeType) -> bool:
        return isinstance(node, PKIRoleNode)

    @override
    async def _flush(self, node: NodeType) -> None:
        assert isinstance(node, PKIRoleNode), node

        payload = node.payload

        await self.observer.trigger(event.PKIRoleApplicationInitiated(payload))

        result = {}

        try:
            result = await self.pki_role_svc.apply(payload)
        except Exception as exc:
            ev, result = (
                event.PKIRoleVerifyError(payload),
                ApplyResult(status="verify_error", error=exc),
            )
        else:
            match result.get("status"):
                case "verify_success":
                    ev = event.PKIRoleVerifySuccess(payload)
                case "verify_error":
                    ev = event.PKIRoleVerifyError(payload)
                case "update_success":
                    ev = event.PKIRoleUpdateSuccess(payload)
                case "update_error":
                    ev = event.PKIRoleUpdateError(payload)
                case "create_success":
                    ev = event.PKIRoleCreateSuccess(payload)
                case "create_error":
                    ev = event.PKIRoleCreateError(payload)
                case _ as status:
                    raise NotImplementedError(status)
        finally:
            if "ev" in locals().keys():
                logger.debug("applying finished %r", payload.absolute_path())

                await self.observer.trigger(ev)

        if error := result.get("error"):
            raise error
