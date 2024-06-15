import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Sequence

from typing_extensions import override

from .. import dto
from ..dispatcher import event
from ..service import PKIRoleService
from ..util.dependency_chain import AbstractNode
from .abstract import ChainBasedProcessor
from .issuer import IssuerFallbackNode

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PKIRoleNode(AbstractNode):
    payload: dto.PKIRoleApplyDTO

    @override
    def __hash__(self) -> int:
        return hash(self.payload.absolute_path())

    @classmethod
    def from_payload(cls, payload: dto.PKIRoleApplyDTO) -> "PKIRoleNode":
        return cls(payload)


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

        return (
            IssuerFallbackNode.from_issuer_absolute_path(
                node.payload.issuer_ref_absolute_path()
            ),
        )

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
        return IssuerFallbackNode.from_issuer_absolute_path(ev.resource.absolute_path())

    @override
    def downstream_selector(self, node: NodeType) -> bool:
        return isinstance(node, PKIRoleNode)

    @override
    async def _flush(self, node: NodeType) -> None:
        assert isinstance(node, PKIRoleNode), node

        await self.observer.trigger(event.PKIRoleApplicationInitiated(node.payload))

        # TODO: VerifySuccess, VerifyError, UpdateSuccess, UpdateError
        try:
            await self.pki_role_svc.update_or_create(node.payload)
        except Exception:
            await self.observer.trigger(event.PKIRoleCreateError(node.payload))
            raise

        logger.debug("applying finished %r", node.payload.absolute_path())

        await self.observer.trigger(event.PKIRoleCreateSuccess(node.payload))
