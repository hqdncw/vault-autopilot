from dataclasses import InitVar, dataclass, field

from .. import service
from .._pkg import asyva


@dataclass(slots=True)
class PasswordPolicyState:
    client: InitVar[asyva.Client]
    pwd_policy_svc: service.PasswordPolicyService = field(init=False)

    def __post_init__(self, client: asyva.Client) -> None:
        self.pwd_policy_svc = service.PasswordPolicyService(client)
