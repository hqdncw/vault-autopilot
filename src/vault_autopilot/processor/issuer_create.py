import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from vault_autopilot import dep_manager

from .. import dto, state, util

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class IssuerNode(dep_manager.AbstractNode):
    payload: Any
    is_ref: bool

    def __hash__(self) -> int:
        return hash(self.payload)

    @classmethod
    def create_from_payload(cls, payload: dto.IssuerCreateDTO) -> "IssuerNode":
        """
        Creates a new instance of the class.

        Args:
            payload: The payload containing the information to create the IssuerNode.
            status: The initial status of the node.
        """
        return cls(payload, False)

    @classmethod
    def create_reference(cls, path: str) -> "IssuerNode":
        """
        Creates a reference to an issuer node without fully loading its details. This
        allows for efficient ordering of dependencies even when the issuer's details are
        not yet available.
        """
        return cls(path, True)


@dataclass(slots=True)
class IssuerCreateProcessor:
    state: state.IssuerState
    sem: asyncio.Semaphore

    async def _process(self, payload: dto.IssuerCreateDTO) -> None:
        """Processes the given payload."""
        await self.state.iss_svc.create(payload)

    async def _fulfill_unsatisfied_successors(
        self,
        predecessor: IssuerNode,
    ) -> None:
        async with self.state.dep_mgr.lock() as mgr:
            for sucr in (
                unsatisfied_sucrs := tuple(mgr.find_unsatisfied_nodes(predecessor))
            ):
                mgr.update_status(
                    predecessor=predecessor, successor=sucr, status="in_process"
                )

        async with asyncio.TaskGroup() as tg:
            for sucr in unsatisfied_sucrs:
                logger.debug("creating task for successor %r", hash(sucr))
                await util.coro.create_task_throttled(
                    tg, self.sem, self._process(sucr.payload)
                )

        if not unsatisfied_sucrs:
            logger.debug("no outbound edges were found for node %r", hash(predecessor))
            return

        async with self.state.dep_mgr.lock() as mgr:
            for sucr in unsatisfied_sucrs:
                mgr.update_status(
                    predecessor=predecessor, successor=sucr, status="satisfied"
                )

        for sucr in unsatisfied_sucrs:
            await self._fulfill_unsatisfied_successors(predecessor=sucr)

    async def process(self, payload: dto.IssuerCreateDTO) -> None:
        """
        Schedules a request to create a new issuer on the Vault server. The payload
        should contain information about the issuer, such as its name and any relevant
        issuance parameters.

        If the payload includes issuance parameters, we first check if the specified
        Certificate Authority (CA) already exists on the Vault server. If it does, we
        schedule all known successors linked to that CA, including the current one, to
        be created on the Vault server. This sets up a proper dependency chain between
        the new issuer and the existing CA hierarchy, allowing the new issuer to issue
        certificates that chain up to the root CA.

        If the payload doesn't include issuance parameters, we schedule the issuer with
        the given payload to be created immediately, without establishing any
        dependencies. In this case, the new issuer is self-signed, meaning it issues its
        own certificate without relying on any other issuer or CA hierarchy.

        If the payload contains issuance parameters but the issuing CA hasn't been set
        up on the Vault server yet, we'll create the dependent issuer (using the
        provided payload) at a later time when the CA hierarchy is established.

        Args:
            payload: The IssuerCreateDTO containing the information about the new
                issuer.
        """
        if not (iss_params := bool(payload.spec.get("issuance_params"))):
            await self._process(payload)

        async with self.state.dep_mgr.lock() as mgr:
            if iss_params:
                successor = IssuerNode.create_from_payload(payload)
                predecessor = IssuerNode.create_reference(
                    payload.get_issuing_authority_full_path()
                )
                mgr.add_node(successor)
                mgr.add_edge(predecessor, successor, "unsatisfied")

                if not (
                    mgr.is_node_exists(predecessor)
                    and mgr.are_edges_satisfied(predecessor)
                ):
                    # skip creating successors as the predecessor is not yet available
                    return
            else:
                predecessor = IssuerNode.create_from_payload(payload)
                mgr.add_node(predecessor)

        await self._fulfill_unsatisfied_successors(predecessor)

    async def postprocess(self) -> None:
        """
        Forces the creation of issuers with unsatisfied dependencies. This can be useful
        in certain scenarios, such as when the issuer is not recognized or there are
        cyclic dependencies. May lead to errors, but provides valuable insights for
        resolution.
        """
        async with asyncio.TaskGroup() as tg:
            async with self.state.dep_mgr.lock() as mgr:
                for node in mgr.find_all_unsatisfied_nodes():
                    logger.debug("force node to be processed: %r", node)
                    await util.coro.create_task_throttled(
                        tg, self.sem, self._process(node.payload)
                    )
