from typing import Literal

from .abstract import VersionedSecretApplyDTO


class PasswordApplyDTO(VersionedSecretApplyDTO):
    class Spec(VersionedSecretApplyDTO.Spec):
        secret_key: str
        policy_path: str

    kind: Literal["Password"] = "Password"
    spec: Spec

    def absolute_path(self) -> str:
        return "/".join((self.spec["secrets_engine"], self.spec["path"]))
