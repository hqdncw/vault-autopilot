import asyncio
import itertools
from dataclasses import dataclass
from typing import Sequence, Union, cast

from .. import dto, state, util
from ..dispatcher import event
from . import abstract


@dataclass(slots=True)
class PasswordNode(util.dep_manager.AbstractNode):
    payload: dto.PasswordInitializeDTO

    def __hash__(self) -> int:
        return hash(self.payload.absolute_path())

    @classmethod
    def from_payload(cls, payload: dto.PasswordInitializeDTO) -> "PasswordNode":
        return cls(payload)


@dataclass(slots=True)
class PasswordPolicyNode(util.dep_manager.AbstractNode):
    node_hash: int

    def __hash__(self) -> int:
        return self.node_hash

    @classmethod
    def from_path(cls, path: str) -> "PasswordPolicyNode":
        return cls(hash(path))


NodeType = Union[PasswordNode, PasswordPolicyNode]


@dataclass(slots=True)
class PasswordInitializeProcessor(abstract.AbstractProcessor):
    state: state.PasswordState

    def register_handlers(self) -> None:
        async def _on_password_discovered(ev: event.PasswordDiscovered) -> None:
            """
            Responds to the :class:`event.PasswordDiscovered` event by handling newly
            discovered passwords and ensuring they are processed correctly.

            When a new password is discovered, this function takes the following
            actions:

            #. Checks if the policy specified in the password payload is already
               initialized. If so, proceeds with processing the payload immediately.
            #. If the password policy is not yet initialized (i.e., it has not been
               parsed from the manifest yet), adds the password to the dependency
               manager and sets its status to "unsatisfied". This indicates that the
               password is waiting for the policy to be initialized before it can be
               processed.

            See also:
                :meth:`_on_password_policy_initialized`
            """
            # policy, pwd = PasswordPolicyNode.from_path(
            #     ev.payload.spec["policy_path"]
            # ), PasswordNode.from_payload(ev.payload)

            async with self.state.dep_mgr.lock() as mgr:
                if (
                    pwd := mgr.get_node_by_hash(hash(ev.payload.absolute_path()), None)
                ) is None:
                    pwd = PasswordNode.from_payload(ev.payload)
                    mgr.add_node(pwd)
                else:
                    raise RuntimeError("Duplicates aren't allowed: %r" % ev.payload)

                if (
                    policy := mgr.get_node_by_hash(
                        (policy_hash := hash(ev.payload.spec["policy_path"])), None
                    )
                ) is None:
                    policy = PasswordPolicyNode(node_hash=policy_hash)
                    mgr.add_node(policy)
                    mgr.add_edge(policy, pwd, "unsatisfied")
                    return
                else:
                    mgr.update_edge_status(policy, pwd, "in_process")

            await self._process(ev.payload)

            async with self.state.dep_mgr.lock() as mgr:
                mgr.update_edge_status(policy, pwd, "satisfied")

        async def _on_password_policy_initialized(
            ev: event.PasswordPolicyInitialized,
        ) -> None:
            """
            Responds to the :class:`event.PasswordPolicyInitialized` event by processing
            any uninitialized password nodes that depend on the initialized policy.

            Args:
                ev: The event triggered by the system when a password policy is
                    initialized.
            """
            async with self.state.dep_mgr.lock() as mgr:
                if (
                    policy := mgr.get_node_by_hash(
                        (policy_hash := hash(ev.payload.spec["path"])), None
                    )
                ) is None:
                    policy = PasswordPolicyNode(node_hash=policy_hash)
                    mgr.add_node(policy)
                else:
                    assert isinstance(policy, PasswordPolicyNode)

                nodes = cast(
                    tuple[PasswordNode, ...], tuple(mgr.find_unsatisfied_nodes(policy))
                )
                for pwd in nodes:
                    assert isinstance(pwd, PasswordNode)
                    mgr.update_edge_status(policy, pwd, status="in_process")

            await self._batch_process(policy, nodes)

        async def _on_postprocess_requested(_: event.PostProcessRequested) -> None:
            """
            Respond to post-processing requests by processing any uninitialized
            passwords.

            Args:
                _: The event triggered by the dispatcher when post-processing is
                    requested.
            """
            await self._force_password_init_despite_policy_absence()

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
            _on_password_policy_initialized,
        )
        self.state.observer.register(
            (event.PostProcessRequested,), _on_postprocess_requested
        )

    async def _process(self, payload: dto.PasswordInitializeDTO) -> None:
        # TODO: Unchanged/Updated events
        await self.state.pwd_svc.create(payload)
        await self.state.observer.trigger(event.PasswordCreated(payload))

    async def _batch_process(
        self, policy: PasswordPolicyNode, pwd_nodes: Sequence[PasswordNode]
    ) -> None:
        async with asyncio.TaskGroup() as tg:
            for node in pwd_nodes:
                await util.coro.create_task_limited(
                    tg, self.state.sem, self._process(node.payload)
                )

        async with self.state.dep_mgr.lock() as mgr:
            for node in pwd_nodes:
                mgr.update_edge_status(policy, node, status="satisfied")

            # Optimize memory usage by removing unnecessary nodes and edges, as the
            # password has already been generated.
            mgr.remove_nodes(pwd_nodes)

    async def _force_password_init_despite_policy_absence(self) -> None:
        """
        Initializes passwords for which the policy has not yet been initialized.
        """
        async with self.state.dep_mgr.lock() as mgr:
            edges = cast(
                tuple[tuple[PasswordPolicyNode, PasswordNode], ...],
                tuple(mgr.find_all_unsatisfied_edges()),
            )

            for policy, pwd in edges:
                assert isinstance(policy, PasswordPolicyNode) and isinstance(
                    pwd, PasswordNode
                )
                mgr.update_edge_status(policy, pwd, status="in_process")

        async with asyncio.TaskGroup() as tg:
            for policy, node_batch in itertools.groupby(edges, key=lambda t: t[0]):
                await util.coro.create_task_limited(
                    tg,
                    util.coro.BoundlessSemaphore(),
                    self._batch_process(policy, tuple(pair[1] for pair in node_batch)),
                )
