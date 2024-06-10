from typing import Literal

from typing_extensions import TypedDict

from .._pkg.asyva.dto import pki_role
from .abstract import AbstractDTO


class PKIRoleSpec(TypedDict):
    name: str
    secrets_engine: str
    role: pki_role.PKIRoleFields


class PKIRoleApplyDTO(AbstractDTO):
    kind: Literal["PKIRole"] = "PKIRole"
    spec: PKIRoleSpec

    def absolute_path(self) -> str:
        return "/".join((self.spec["secrets_engine"], self.spec["name"]))

    def issuer_ref_absolute_path(self) -> str:
        return "/".join((self.spec["secrets_engine"], self.spec["role"]["issuer_ref"]))
