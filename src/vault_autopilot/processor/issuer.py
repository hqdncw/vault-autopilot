import logging
from dataclasses import dataclass, field
from typing import Iterable
from typing_extensions import override

from ..util.dependency_chain import AbstractNode, FallbackNode

from .. import dto
from ..dispatcher import event
from ..service.abstract import ApplyResult, ApplyResultStatus
from ..service import IssuerService
from .abstract import ChainBasedProcessor

logger = logging.getLogger(__name__)

STATUS_EVENT_MAPPING: dict[
    ApplyResultStatus,
    type[event.IssuerApplySuccess | event.IssuerApplyError],
] = {
    "verify_success": event.IssuerVerifySuccess,
    "create_success": event.IssuerCreateSuccess,
    "update_success": event.IssuerUpdateSuccess,
    "verify_error": event.IssuerVerifyError,
    "create_error": event.IssuerCreateError,
    "update_error": event.IssuerUpdateError,
}


@dataclass(slots=True)
class IssuerNode(AbstractNode):
    payload: dto.IssuerApplyDTO = field(repr=False)

    @override
    def __hash__(self) -> int:
        return hash(self.payload.absolute_path())

    @classmethod
    def from_payload(cls, payload: dto.IssuerApplyDTO) -> "IssuerNode":
        """
        Creates a node from given payload.

        Args:
            payload: The payload to create the node from.

        Returns:
            A new instance of the IssuerNode class.
        """
        return cls(payload)


@dataclass(slots=True)
class IssuerFallbackNode(FallbackNode):
    @classmethod
    def from_issuer_absolute_path(cls, path: str) -> "IssuerFallbackNode":
        """
        Creates a new :class:`IssuerFallbackNode` instance from an issuer absolute path.

        Args:
            path: The path must be in the format ``pki/my-issuer`` where ``pki`` is the
                PKI engine mount path and ``my-issuer`` is the name of the issuer.
        """
        return cls(hash(path))


NodeType = IssuerNode | IssuerFallbackNode


@dataclass(slots=True)
class IssuerApplyProcessor(ChainBasedProcessor[NodeType]):
    iss_svc: IssuerService

    @override
    async def _build_fallback_upstream_nodes(
        self, node: NodeType
    ) -> Iterable[NodeType]:
        assert isinstance(
            node, IssuerNode
        ), "You can't build fallbacks for the node that is fallback itself"

        if node.payload.spec.get("chaining"):
            return (
                IssuerFallbackNode.from_issuer_absolute_path(
                    node.payload.upstream_issuer_absolute_path()
                ),
            )

        return ()

    @override
    def initialize(self) -> None:
        async def _on_issuer_apply_requested(ev: event.IssuerApplyRequested) -> None:
            await self.schedule(IssuerNode.from_payload(ev.resource))

        async def _on_postprocess_requested(_: event.PostProcessRequested) -> None:
            await self.flush_any_pending_downstreams()

        self.observer.register(
            (event.IssuerApplyRequested,), _on_issuer_apply_requested
        )
        self.observer.register((event.PostProcessRequested,), _on_postprocess_requested)

    @override
    async def _flush(self, node: NodeType) -> None:
        assert isinstance(node, IssuerNode)

        await self.observer.trigger(event.IssuerApplyStarted(node.payload))

        try:
            result = await self.iss_svc.apply(node.payload)
        except Exception as ex:
            result = ApplyResult(status="verify_error", errors=(ex,))

        await self.observer.trigger(
            STATUS_EVENT_MAPPING[result["status"]](node.payload)
        )

        if errors := result.get("errors"):
            raise ExceptionGroup("Failed to apply issuer", errors)

        logger.debug("applying finished %r", node.payload.absolute_path())
