import logging
from dataclasses import dataclass
from typing import Iterable, Sequence

from typing_extensions import override

from vault_autopilot.service.abstract import ApplyResult

from .. import dto, util
from ..dispatcher import event
from ..service import SSHKeyService
from .abstract import (
    ChainBasedProcessor,
    SecretsEngineFallbackNode,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SSHKeyNode(util.dependency_chain.AbstractNode):
    payload: dto.SSHKeyApplyDTO

    @override
    def __hash__(self) -> int:
        return hash(self.payload.absolute_path())

    @classmethod
    def from_payload(cls, payload: dto.SSHKeyApplyDTO) -> "SSHKeyNode":
        return cls(payload)


NodeType = SSHKeyNode | SecretsEngineFallbackNode


@dataclass(slots=True)
class SSHKeyApplyProcessor(
    ChainBasedProcessor[NodeType, event.EventType],
):
    ssh_key_svc: SSHKeyService

    @override
    async def _build_fallback_upstream_nodes(
        self, node: NodeType
    ) -> Iterable[NodeType]:
        assert isinstance(node, SSHKeyNode), node

        return (
            SecretsEngineFallbackNode.from_absolute_path(
                node.payload.spec["secrets_engine"]
            ),
        )

    @override
    def initialize(self) -> None:
        async def _on_ssh_key_apply_requested(
            ev: event.SSHKeyApplicationRequested,
        ) -> None:
            await self.schedule(SSHKeyNode.from_payload(ev.resource))

        self.observer.register(
            (event.SSHKeyApplicationRequested,), _on_ssh_key_apply_requested
        )

        ChainBasedProcessor.initialize(self)

    @property
    def upstream_dependency_triggers(
        self,
    ) -> Sequence[type[event.SecretsEngineApplySuccess]]:
        return (
            event.SecretsEngineCreateSuccess,
            event.SecretsEngineUpdateSuccess,
            event.SecretsEngineVerifySuccess,
        )

    @override
    def upstream_node_builder(self, ev: event.EventType) -> NodeType:
        assert isinstance(ev, event.SecretsEngineApplySuccess), ev
        return SecretsEngineFallbackNode.from_absolute_path(ev.resource.spec["path"])

    @override
    def downstream_selector(self, node: NodeType) -> bool:
        return isinstance(node, SSHKeyNode)

    async def _flush(self, node: NodeType) -> None:
        assert isinstance(node, SSHKeyNode), node

        payload = node.payload

        await self.observer.trigger(event.SSHKeyApplicationInitiated(payload))

        ev: event.SSHKeyApplySuccess | event.SSHKeyApplyError

        result = {}

        try:
            result = await self.ssh_key_svc.apply(payload)
        except Exception as exc:
            ev, result = (
                event.SSHKeyCreateError(payload),
                ApplyResult(status="create_error", errors=(exc,)),
            )
        else:
            match result.get("status"):
                case "verify_success":
                    ev = event.SSHKeyVerifySuccess(payload)
                case "verify_error":
                    ev = event.SSHKeyVerifyError(payload)
                case "update_success":
                    ev = event.SSHKeyUpdateSuccess(payload)
                case "update_error":
                    ev = event.SSHKeyUpdateError(payload)
                case "create_success":
                    ev = event.SSHKeyCreateSuccess(payload)
                case "create_error":
                    ev = event.SSHKeyCreateError(payload)
                case _ as status:
                    raise NotImplementedError(status)
        finally:
            logger.debug("applying finished %r", payload.absolute_path())
            await self.observer.trigger(ev)

        if errors := result.get("errors"):
            raise ExceptionGroup("Failed to apply ssh key", errors)
