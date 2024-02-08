import logging
from dataclasses import dataclass
from typing import Iterable, Type, Union

from .. import dto, state, util
from ..dispatcher import event
from ..service.abstract import ApplyResult, ApplyResultStatus
from . import abstract

logger = logging.getLogger(__name__)


APPLY_STATUS_EVENT_MAP: dict[
    ApplyResultStatus,
    Type[Union[event.PasswordApplySuccess, event.PasswordApplyError]],
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

    def __hash__(self) -> int:
        return hash(self.payload.absolute_path())

    @classmethod
    def from_payload(cls, payload: dto.PasswordApplyDTO) -> "PasswordNode":
        return cls(payload)


@dataclass(slots=True)
class PasswordPolicyNode(util.dependency_chain.AbstractNode):
    node_hash: int

    def __hash__(self) -> int:
        return self.node_hash

    @classmethod
    def from_path(cls, path: str) -> "PasswordPolicyNode":
        return cls(hash(path))


NodeType = Union[PasswordNode, PasswordPolicyNode]


@dataclass(slots=True)
class PasswordApplyProcessor(abstract.ChainBasedProcessor[NodeType]):
    state: state.PasswordState

    async def build_upstreams(self, node: NodeType) -> Iterable[NodeType]:
        assert isinstance(node, PasswordNode)

        return (PasswordPolicyNode.from_path(node.payload.spec["path"]),)

    def register_handlers(self) -> None:
        async def _on_password_apply_requested(
            ev: event.PasswordApplyRequested,
        ) -> None:
            await self._schedule(PasswordNode.from_payload(ev.resource))

        async def _on_password_policy_processed(
            ev: event.PasswordPolicyApplySuccess,
        ) -> None:
            async with self.state.dep_chain.lock() as mgr:
                policy_node = PasswordPolicyNode.from_path(ev.resource.spec["path"])
                if not mgr.has_node(policy_node):
                    mgr.add_node(policy_node)

            await self.satisfy_outbound_edges_for(
                PasswordPolicyNode.from_path(ev.resource.absolute_path())
            )

        async def _on_postprocess_requested(_: event.PostProcessRequested) -> None:
            await self.satisfy_any_downstreams()

        self.state.observer.register(
            (event.PasswordApplyRequested,),
            _on_password_apply_requested,
        )
        self.state.observer.register(
            (
                event.PasswordPolicyCreateSuccess,
                event.PasswordPolicyUpdateSuccess,
                event.PasswordPolicyVerifySuccess,
            ),
            _on_password_policy_processed,
        )
        self.state.observer.register(
            (event.PostProcessRequested,), _on_postprocess_requested
        )

    async def _process(self, node: NodeType) -> None:
        assert isinstance(node, PasswordNode)

        await self.state.observer.trigger(event.PasswordApplyRequested(node.payload))

        try:
            result = await self.state.pwd_svc.apply(node.payload)
        except Exception as ex:
            result = ApplyResult(status="verify_error", errors=(ex,))

        await self.state.observer.trigger(
            APPLY_STATUS_EVENT_MAP[result["status"]](node.payload)
        )

        if errors := result.get("errors"):
            raise ExceptionGroup("Failed to apply password", errors)

        logger.debug(
            "password resource applying finished: %r", node.payload.absolute_path()
        )
