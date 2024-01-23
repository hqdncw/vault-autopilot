import asyncio
import typing
from dataclasses import InitVar, dataclass, field

import ironfence

from .. import service, util
from .._pkg import asyva
from ..processor.abstract import ChainBasedProcessorState

if typing.TYPE_CHECKING:
    from ..dispatcher import event
    from ..processor.issuer import NodeType


@dataclass(slots=True)
class IssuerState(ChainBasedProcessorState["NodeType"]):
    client: InitVar[asyva.Client]
    iss_svc: service.IssuerService = field(init=False)
    dep_chain: ironfence.Mutex[
        util.dependency_chain.DependencyChain["NodeType"]
    ] = field(init=False)
    sem: asyncio.Semaphore
    observer: "event.EventObserver[event.EventType]"

    def __post_init__(self, client: asyva.Client) -> None:
        self.iss_svc = service.IssuerService(client)
        self.dep_chain = ironfence.Mutex(util.dependency_chain.DependencyChain())
