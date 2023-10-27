import typing
from dataclasses import InitVar, dataclass

import ironfence

from .. import dep_manager, service
from .._pkg import asyva

if typing.TYPE_CHECKING:
    from ..processor.issuer_create import IssuerNode


@dataclass
class IssuerState:
    __slots__ = "client", "iss_svc", "dep_mgr"

    client: InitVar[asyva.Client]

    def __post_init__(self, client: asyva.Client) -> None:
        self.iss_svc = service.IssuerService(client)
        self.dep_mgr: ironfence.Mutex[
            dep_manager.DependencyManager[IssuerNode]
        ] = ironfence.Mutex(dep_manager.DependencyManager())
