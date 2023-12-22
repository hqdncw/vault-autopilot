import asyncio
import typing
from dataclasses import InitVar, dataclass, field

import ironfence

from .. import service, util
from .._pkg import asyva

if typing.TYPE_CHECKING:
    from ..dispatcher import event
    from ..processor.password_create import NodeType


@dataclass(slots=True)
class PasswordState:
    client: InitVar[asyva.Client]
    pwd_svc: service.PasswordService = field(init=False)
    dep_mgr: ironfence.Mutex[util.dep_manager.DependencyManager["NodeType"]] = field(
        init=False
    )
    sem: asyncio.Semaphore
    observer: "event.EventObserver[event.EventType]"

    def __post_init__(self, client: asyva.Client) -> None:
        self.pwd_svc = service.PasswordService(client)
        self.dep_mgr = ironfence.Mutex(util.dep_manager.DependencyManager())
