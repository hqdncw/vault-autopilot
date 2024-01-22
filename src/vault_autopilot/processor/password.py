import logging
from dataclasses import dataclass
from typing import Iterable, Union

from .. import dto, state, util
from ..dispatcher import event
from .abstract import ChainBasedProcessor

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PasswordNode(util.dependency_chain.AbstractNode):
    payload: dto.PasswordCheckOrSetDTO

    def __hash__(self) -> int:
        return hash(self.payload.absolute_path())

    @classmethod
    def from_payload(cls, payload: dto.PasswordCheckOrSetDTO) -> "PasswordNode":
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
class PasswordCheckOrSetProcessor(ChainBasedProcessor[NodeType]):
    state: state.PasswordState

    async def get_upstreams(self, node: NodeType) -> Iterable[NodeType]:
        assert isinstance(node, PasswordNode)

        return (PasswordPolicyNode.from_path(node.payload.spec["path"]),)

    def register_handlers(self) -> None:
        async def _on_password_discovered(ev: event.PasswordDiscovered) -> None:
            await self._schedule(PasswordNode.from_payload(ev.payload))

        async def _on_password_policy_processed(
            ev: event.PasswordPolicyProcessed,
        ) -> None:
            async with self.state.dep_chain.lock() as mgr:
                policy_node = PasswordPolicyNode.from_path(ev.payload.spec["path"])
                if not mgr.has_node(policy_node):
                    mgr.add_node(policy_node)

            await self._satisfy_downstreams(
                PasswordPolicyNode.from_path(ev.payload.absolute_path())
            )

        async def _on_postprocess_requested(_: event.PostProcessRequested) -> None:
            await self._satisfy_remaining_downstreams()

        self.state.observer.register(
            (event.PasswordDiscovered,),
            _on_password_discovered,
        )
        self.state.observer.register(
            (
                event.PasswordPolicyCreated,
                event.PasswordPolicyUpdated,
                event.PasswordPolicyUnchanged,
            ),
            _on_password_policy_processed,
        )
        self.state.observer.register(
            (event.PostProcessRequested,), _on_postprocess_requested
        )

    async def _process(self, node: NodeType) -> None:
        assert isinstance(node, PasswordNode)

        await self.state.pwd_svc.create(node.payload)
        logger.debug(
            "completed processing of password %r", node.payload.absolute_path()
        )

        # TODO: Unchanged/Updated events
        await self.state.observer.trigger(event.PasswordCreated(node.payload))
