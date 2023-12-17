import asyncio
import logging
from dataclasses import dataclass
from typing import Union

from .. import dto, state, util

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Node(util.dep_manager.AbstractNode):
    payload: dto.IssuerCreateDTO

    def __hash__(self) -> int:
        return hash("{0[secret_engine]}/{0[name]}".format(self.payload["spec"]))

    @classmethod
    def from_payload(cls, payload: dto.IssuerCreateDTO) -> "Node":
        """
        Creates a node from given payload.

        Args:
            payload: The payload containing the information to create the node.
            status: The initial status of the node.
        """
        return cls(payload)


@dataclass(slots=True)
class NodeReference:
    """A reference to a :class:`Node` object. This allows for efficient ordering of
    dependencies even when the issuer's details are not yet available.

    Args:
        node_hash: The hash of the referenced node."""

    node_hash: int

    def __hash__(self) -> int:
        return self.node_hash

    @classmethod
    def from_issuer_ref(cls, issuer_ref: str) -> "NodeReference":
        """
        Creates a reference to a node.

        Args:
            issuer_ref: The PKI engine mount path followed by the issuer name, separated
                by a forward slash. For example: ``pki/my-issuer``.
        """
        return cls(hash(issuer_ref))


NodeType = Union[Node, NodeReference]


@dataclass(slots=True)
class IssuerCreateProcessor:
    state: state.IssuerState
    sem: asyncio.Semaphore

    async def _process(self, payload: dto.IssuerCreateDTO) -> None:
        """Processes the given payload."""
        await self.state.iss_svc.create(payload)

    async def _create_task(
        self, tg: asyncio.TaskGroup, payload: dto.IssuerCreateDTO
    ) -> None:
        await util.coro.create_task_throttled(tg, self.sem, self._process(payload))

    async def _fulfill_unsatisfied_successors(
        self,
        predecessor: NodeType,
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
                assert isinstance(sucr, Node)
                await self._create_task(tg, sucr.payload)

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
        Schedule creation of a new issuer on the Vault server.

        If the payload includes issuance parameters, the function will:

            - Check if the root issuer already exists on the Vault server.
            - If the root issuer exists, schedule all known intermediates, including the
              current one, to be created on the Vault server, setting up a proper
              dependency chain.
            - If the root issuer does not exist, create the given intermediate issuer
              later when the root CA is set up.

        If the payload does not include issuance parameters, the function will create
        the issuer immediately without establishing dependencies.

        Args:
            payload: The payload containing the information about the new issuer.

        See also:
            :meth:`postprocess`
        """
        if not (iss_params := payload["spec"].get("issuance_params")):
            await self._process(payload)

        async with self.state.dep_mgr.lock() as mgr:
            predecessor: NodeType
            if iss_params:
                successor = Node.from_payload(payload)
                predecessor = NodeReference.from_issuer_ref(iss_params["issuer_ref"])
                mgr.add_node(successor)
                mgr.add_edge(predecessor, successor, "unsatisfied")

                if not (
                    mgr.is_node_exists(predecessor)
                    and mgr.are_edges_satisfied(predecessor)
                ):
                    # skip creating successors as the predecessor is not yet available
                    return
            else:
                predecessor = Node.from_payload(payload)
                mgr.add_node(predecessor)

        await self._fulfill_unsatisfied_successors(predecessor)

    async def postprocess(self) -> None:
        """
        Forces creation of issuers with unsatisfied dependencies, aiding in resolving
        recognition and cyclic dependency issues, but may cause errors and requires
        careful analysis for resolution.
        """
        async with asyncio.TaskGroup() as tg:
            async with self.state.dep_mgr.lock() as mgr:
                for node in mgr.find_all_unsatisfied_nodes():
                    assert isinstance(node, Node)
                    logger.debug("force node to be processed: %r", node)
                    await self._create_task(tg, node.payload)
