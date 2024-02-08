from typing import Literal

from typing_extensions import TypedDict

from .._pkg.asyva.dto import pki_role
from . import abstract


class PKIRoleSpec(TypedDict):
    name: str
    secret_engine: str
    role: pki_role.PKIRoleFields


class PKIRoleApplyDTO(abstract.AbstractDTO):
    kind: Literal["PKIRole"] = "PKIRole"
    spec: PKIRoleSpec

    def absolute_path(self) -> str:
        return "/".join((self.spec["secret_engine"], self.spec["name"]))

    def issuer_ref_absolute_path(self) -> str:
        return "/".join((self.spec["secret_engine"], self.spec["role"]["issuer_ref"]))
