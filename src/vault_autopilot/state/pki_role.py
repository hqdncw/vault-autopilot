import asyncio
import typing
from dataclasses import InitVar, dataclass, field

import ironfence

from .. import service, util
from .._pkg import asyva
from ..processor.abstract import ChainBasedProcessorState

if typing.TYPE_CHECKING:
    from ..dispatcher.dispatcher import event
    from ..processor.pki_role import NodeType


@dataclass(slots=True, kw_only=True)
class PKIRoleState(ChainBasedProcessorState["NodeType"]):
    client: InitVar[asyva.Client]
    pki_role_svc: service.PKIRoleService = field(init=False)
    sem: asyncio.Semaphore
    observer: "event.EventObserver[event.EventType]"
    dep_chain: ironfence.Mutex[
        util.dependency_chain.DependencyChain["NodeType"]
    ] = field(
        default_factory=lambda: ironfence.Mutex(util.dependency_chain.DependencyChain())
    )

    def __post_init__(self, client: asyva.Client) -> None:
        self.pki_role_svc = service.PKIRoleService(client)
