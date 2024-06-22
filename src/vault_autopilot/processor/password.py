import logging
from dataclasses import dataclass
from typing import Iterable, Sequence

from typing_extensions import override

from .. import dto, util
from ..dispatcher import event
from ..service import PasswordService
from ..service.abstract import ApplyResult, ApplyResultStatus
from .abstract import (
    ChainBasedProcessor,
    SecretsEngineFallbackNode,
)

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


NodeType = PasswordNode | PasswordPolicyFallbackNode | SecretsEngineFallbackNode


@dataclass(slots=True)
class PasswordApplyProcessor(ChainBasedProcessor[NodeType, event.EventType]):
    pwd_svc: PasswordService

    @override
    async def _build_fallback_upstream_nodes(
        self, node: NodeType
    ) -> Iterable[NodeType]:
        assert isinstance(node, PasswordNode), node

        return (
            PasswordPolicyFallbackNode.from_path(node.payload.spec["policy_path"]),
            SecretsEngineFallbackNode.from_absolute_path(
                node.payload.spec["secrets_engine"]
            ),
        )

    @override
    def initialize(self) -> None:
        async def _on_password_apply_requested(
            ev: event.PasswordApplicationRequested,
        ) -> None:
            await self.schedule(PasswordNode.from_payload(ev.resource))

        self.observer.register(
            (event.PasswordApplicationRequested,),
            _on_password_apply_requested,
        )

        ChainBasedProcessor.initialize(self)

    @property
    def upstream_dependency_triggers(
        self,
    ) -> Sequence[
        type[event.SecretsEngineApplySuccess | event.PasswordPolicyApplySuccess]
    ]:
        return (
            event.SecretsEngineCreateSuccess,
            event.SecretsEngineUpdateSuccess,
            event.SecretsEngineVerifySuccess,
            event.PasswordPolicyCreateSuccess,
            event.PasswordPolicyUpdateSuccess,
            event.PasswordPolicyVerifySuccess,
        )

    @override
    def upstream_node_builder(self, ev: event.EventType) -> NodeType:
        if isinstance(ev, event.SecretsEngineApplySuccess):
            return SecretsEngineFallbackNode.from_absolute_path(
                ev.resource.spec["path"]
            )
        elif isinstance(ev, event.PasswordPolicyApplySuccess):
            return PasswordPolicyFallbackNode.from_path(ev.resource.absolute_path())

        raise RuntimeError("Unexpected upstream dependency %r", ev)

    @override
    def downstream_selector(self, node: NodeType) -> bool:
        return isinstance(node, PasswordNode)

    @override
    async def _flush(self, node: NodeType) -> None:
        assert isinstance(node, PasswordNode), node

        payload = node.payload

        await self.observer.trigger(event.PasswordApplicationInitiated(payload))

        try:
            result = await self.pwd_svc.apply(payload)
        except Exception as exc:
            ev, result = (
                event.PasswordCreateError(payload),
                ApplyResult(status="create_error", error=exc),
            )
        else:
            match result.get("status"):
                case "verify_success":
                    ev = event.PasswordVerifySuccess(payload)
                case "verify_error":
                    ev = event.PasswordVerifyError(payload)
                case "update_success":
                    ev = event.PasswordUpdateSuccess(payload)
                case "update_error":
                    ev = event.PasswordUpdateError(payload)
                case "create_success":
                    ev = event.PasswordCreateSuccess(payload)
                case "create_error":
                    ev = event.PasswordCreateError(payload)
                case _ as status:
                    raise NotImplementedError(status)
        finally:
            logger.debug("applying finished %r", payload.absolute_path())
            await self.observer.trigger(ev)

        if error := result.get("error"):
            raise error
