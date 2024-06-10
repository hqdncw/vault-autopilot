from typing import Literal

from .abstract import VersionedSecretApplyDTO


class PasswordSpec(VersionedSecretApplyDTO.Spec):
    secrets_engine: str
    path: str
    secret_key: str
    policy_path: str


class PasswordApplyDTO(VersionedSecretApplyDTO):
    kind: Literal["Password"] = "Password"
    spec: PasswordSpec

    def absolute_path(self) -> str:
        return "/".join((self.spec["secrets_engine"], self.spec["path"]))
