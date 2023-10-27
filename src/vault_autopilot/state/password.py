from dataclasses import InitVar, dataclass

from .. import service
from .._pkg import asyva


@dataclass
class PasswordState:
    __slots__ = ("pwd_svc",)

    client: InitVar[asyva.Client]

    def __post_init__(self, client: asyva.Client) -> None:
        self.pwd_svc = service.PasswordService(client)
