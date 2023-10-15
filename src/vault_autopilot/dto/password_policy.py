from typing import Any

from vault_autopilot._pkg import asyva

from . import base


class PasswordPolicySpec(base.PathSpec, asyva.PasswordPolicy):
    pass


class PasswordPolicyDTO(base.BaseDTO):
    spec: PasswordPolicySpec

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, PasswordPolicyDTO):
            raise TypeError()
        return self.spec.path == other.spec.path
