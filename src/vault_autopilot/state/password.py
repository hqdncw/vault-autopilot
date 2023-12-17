from dataclasses import InitVar, dataclass, field

from .. import service
from .._pkg import asyva


@dataclass(slots=True)
class PasswordState:
    client: InitVar[asyva.Client]
    pwd_svc: service.PasswordService = field(init=False)

    def __post_init__(self, client: asyva.Client) -> None:
        self.pwd_svc = service.PasswordService(client)
