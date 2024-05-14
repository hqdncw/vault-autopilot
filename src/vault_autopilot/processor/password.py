import logging
from dataclasses import dataclass
from typing import Iterable
from typing_extensions import override


from .. import dto, util
from ..dispatcher import event
from ..service.abstract import ApplyResult, ApplyResultStatus
from ..service import PasswordService
from . import abstract

logger = logging.getLogger(__name__)


APPLY_STATUS_EVENT_MAP: dict[
    ApplyResultStatus,
    type[event.PasswordApplySuccess | event.PasswordApplyError],
] = {
    "verify_success": event.PasswordVerifySuccess,
    "create_success": event.PasswordCreateSuccess,
    "update_success": event.PasswordUpdateSuccess,
    "verify_error": event.PasswordVerifyError,
    "create_error": event.PasswordCreateError,
    "update_error": event.PasswordUpdateError,
}


@dataclass(slots=True)
class PasswordNode(util.dependency_chain.AbstractNode):
    payload: dto.PasswordApplyDTO

    @override
    def __hash__(self) -> int:
        return hash(self.payload.absolute_path())

    @classmethod
    def from_payload(cls, payload: dto.PasswordApplyDTO) -> "PasswordNode":
        return cls(payload)


@dataclass(slots=True)
class PasswordPolicyFallbackNode(util.dependency_chain.AbstractNode):
    node_hash: int

    @override
    def __hash__(self) -> int:
        return self.node_hash

    @classmethod
    def from_path(cls, path: str) -> "PasswordPolicyFallbackNode":
        return cls(hash(path))


NodeType = PasswordNode | PasswordPolicyFallbackNode


@dataclass(slots=True)
class PasswordApplyProcessor(abstract.ChainBasedProcessor[NodeType]):
    pwd_svc: PasswordService

    @override
    async def _build_fallback_upstream_nodes(
        self, node: NodeType
    ) -> Iterable[NodeType]:
        assert isinstance(node, PasswordNode)

        return (PasswordPolicyFallbackNode.from_path(node.payload.spec["path"]),)

    @override
    def initialize(self) -> None:
        async def _on_password_apply_requested(
            ev: event.PasswordApplyRequested,
        ) -> None:
            await self.schedule(PasswordNode.from_payload(ev.resource))

        async def _on_password_policy_processed(
            ev: event.PasswordPolicyApplySuccess,
        ) -> None:
            async with self.dep_chain.lock() as mgr:
                policy_node = PasswordPolicyFallbackNode.from_path(
                    ev.resource.spec["path"]
                )
                if not mgr.has_node(policy_node):
                    _ = mgr.add_node(policy_node)

            await self.flush_pending_downstreams_for(
                PasswordPolicyFallbackNode.from_path(ev.resource.absolute_path())
            )

        async def _on_postprocess_requested(_: event.PostProcessRequested) -> None:
            await self.flush_any_pending_downstreams()

        self.observer.register(
            (event.PasswordApplyRequested,),
            _on_password_apply_requested,
        )
        self.observer.register(
            (
                event.PasswordPolicyCreateSuccess,
                event.PasswordPolicyUpdateSuccess,
                event.PasswordPolicyVerifySuccess,
            ),
            _on_password_policy_processed,
        )
        self.observer.register((event.PostProcessRequested,), _on_postprocess_requested)

    @override
    async def _flush(self, node: NodeType) -> None:
        assert isinstance(node, PasswordNode)

        await self.observer.trigger(event.PasswordApplyRequested(node.payload))

        try:
            result = await self.pwd_svc.apply(node.payload)
        except Exception as ex:
            result = ApplyResult(status="verify_error", errors=(ex,))

        await self.observer.trigger(
            APPLY_STATUS_EVENT_MAP[result["status"]](node.payload)
        )

        if errors := result.get("errors"):
            raise ExceptionGroup("Failed to apply password", errors)

        logger.debug("applying finished %r", node.payload.absolute_path())
