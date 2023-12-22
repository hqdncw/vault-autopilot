import asyncio
import typing
from dataclasses import InitVar, dataclass, field

import ironfence

from .. import service, util
from .._pkg import asyva

if typing.TYPE_CHECKING:
    from ..dispatcher import event
    from ..processor.issuer_create import NodeType


@dataclass(slots=True)
class IssuerState:
    client: InitVar[asyva.Client]
    iss_svc: service.IssuerService = field(init=False)
    dep_mgr: ironfence.Mutex[util.dep_manager.DependencyManager["NodeType"]] = field(
        init=False
    )
    sem: asyncio.Semaphore
    observer: "event.EventObserver[event.EventType]"

    def __post_init__(self, client: asyva.Client) -> None:
        self.iss_svc = service.IssuerService(client)
        self.dep_mgr = ironfence.Mutex(util.dep_manager.DependencyManager())
