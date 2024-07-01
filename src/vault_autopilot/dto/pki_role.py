from os import path
from typing import Literal

from typing_extensions import TypedDict

from .._pkg.asyva.dto import pki_role
from .abstract import AbstractDTO


class PKIRoleApplyDTO(AbstractDTO):
    class Spec(TypedDict):
        name: str
        role: pki_role.PKIRoleFields

    kind: Literal["PKIRole"] = "PKIRole"
    spec: Spec

    def secrets_engine_ref(self) -> str:
        return "/".join(self.spec["role"]["issuer_ref"].split("/")[:-1])

    @property
    def issuer_name(self) -> str:
        return self.spec["role"]["issuer_ref"].split("/")[-1]

    def absolute_path(self) -> str:
        return path.join(self.secrets_engine_ref(), self.spec["name"])
