from typing import Literal

from .abstract import VersionedSecretApplyDTO


class PasswordApplyDTO(VersionedSecretApplyDTO):
    class Spec(VersionedSecretApplyDTO.Spec):
        secret_key: str
        policy_ref: str

    kind: Literal["Password"] = "Password"
    spec: Spec

    def absolute_path(self) -> str:
        return "/".join((self.spec["secrets_engine_ref"], self.spec["path"]))
