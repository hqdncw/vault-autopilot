from dataclasses import InitVar, dataclass

from .. import service
from .._pkg import asyva


@dataclass
class PasswordPolicyState:
    client: InitVar[asyva.Client]

    def __post_init__(self, client: asyva.Client) -> None:
        self.pwd_policy_svc = service.PasswordPolicyService(client)
