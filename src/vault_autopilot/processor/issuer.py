import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Iterable

from typing_extensions import override

from .. import dto
from ..dispatcher import event
from ..processor.secrets_engine import SecretsEngineFallbackNode
from ..service import IssuerService
from ..service.abstract import ApplyResult
from .abstract import (
    AbstractFallbackNode,
    AbstractNode,
    ChainBasedProcessor,
)

logger = logging.getLogger(__name__)

NODE_PREFIX = "issuers/"


@dataclass(slots=True)
class IssuerNode(AbstractNode):
    payload: dto.IssuerApplyDTO = field(repr=False)

    def __repr__(self) -> str:
        return (
            f"IssuerNode(node_hash={hash(self)}, absolute_path={self.absolute_path!r})"
        )

    @override
    def __hash__(self) -> int:
        return hash(NODE_PREFIX + self.absolute_path)

    @classmethod
    def from_payload(cls, payload: dto.IssuerApplyDTO) -> "IssuerNode":
        """
        Creates a node from given payload.

        Args:
            payload: The payload to create the node from.

        Returns:
            A new instance of the IssuerNode class.
        """
        return cls(payload.absolute_path(), payload)


@dataclass(slots=True)
class IssuerFallbackNode(AbstractFallbackNode):
    @override
    def __hash__(self) -> int:
        return hash(NODE_PREFIX + self.absolute_path)


NodeType = IssuerNode | IssuerFallbackNode | SecretsEngineFallbackNode


@dataclass(slots=True)
class IssuerApplyProcessor(ChainBasedProcessor[NodeType, event.EventType]):
    iss_svc: IssuerService

    @override
    async def _build_fallback_upstream_nodes(
        self, node: NodeType
    ) -> Iterable[NodeType]:
        assert isinstance(
            node, IssuerNode
        ), "You can't build fallbacks for the node that is fallback itself"

        if node.payload.spec.get("chaining"):
            return (IssuerFallbackNode(node.payload.upstream_issuer_absolute_path()),)

        return (SecretsEngineFallbackNode(node.payload.spec["secrets_engine_ref"]),)

    @override
    async def _flush(self, node: NodeType) -> None:
        assert isinstance(node, IssuerNode), node

        payload = node.payload

        await self.observer.trigger(event.IssuerApplicationInitiated(payload))

        result = {}

        try:
            result = await self.iss_svc.apply(payload)
        except Exception as exc:
            ev, result = (
                event.IssuerVerifyError(payload),
                ApplyResult(status="verify_error", error=exc),
            )
        else:
            match result.get("status"):
                case "verify_success":
                    ev = event.IssuerVerifySuccess(payload)
                case "verify_error":
                    ev = event.IssuerVerifyError(payload)
                case "update_success":
                    ev = event.IssuerUpdateSuccess(payload)
                case "update_error":
                    ev = event.IssuerUpdateError(payload)
                case "create_success":
                    ev = event.IssuerCreateSuccess(payload)
                case "create_error":
                    ev = event.IssuerCreateError(payload)
                case _ as status:
                    raise NotImplementedError(status)
        finally:
            if "ev" in locals().keys():
                logger.debug("applying finished %r", payload.absolute_path())

                await self.observer.trigger(ev)

        if error := result.get("error"):
            raise error

    @override
    def initialize(self) -> None:
        async def _on_issuer_apply_requested(
            ev: event.IssuerApplicationRequested,
        ) -> None:
            await self.schedule(IssuerNode.from_payload(ev.resource))

        self.observer.register(
            (event.IssuerApplicationRequested,), _on_issuer_apply_requested
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
        return SecretsEngineFallbackNode(ev.resource.spec["path"])

    @override
    def downstream_selector(self, node: NodeType) -> bool:
        return isinstance(node, IssuerNode)
