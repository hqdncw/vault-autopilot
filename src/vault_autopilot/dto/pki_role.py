from typing import Literal

from typing_extensions import TypedDict

from .._pkg.asyva.dto import pki_role
from .abstract import AbstractDTO


class PKIRoleApplyDTO(AbstractDTO):
    class Spec(TypedDict):
        name: str
        secrets_engine_path: str
        role: pki_role.PKIRoleFields

    kind: Literal["PKIRole"] = "PKIRole"
    spec: Spec

    def absolute_path(self) -> str:
        return "/".join((self.spec["secrets_engine_path"], self.spec["name"]))

    def issuer_ref_absolute_path(self) -> str:
        return "/".join(
            (self.spec["secrets_engine_path"], self.spec["role"]["issuer_ref"])
        )
