from typing import Union

from .issuer import IssuerApplyDTO, IssuerGetDTO
from .password import PasswordApplyDTO
from .password_policy import PasswordPolicyApplyDTO
from .pki_role import PKIRoleApplyDTO

DTO = Union[
    IssuerApplyDTO,
    PasswordApplyDTO,
    PasswordPolicyApplyDTO,
    PKIRoleApplyDTO,
]
VersionedSecretApplyDTO = PasswordApplyDTO

__all__ = (
    "DTO",
    "VersionedSecretApplyDTO",
    "IssuerApplyDTO",
    "IssuerGetDTO",
    "PasswordApplyDTO",
    "PasswordPolicyApplyDTO",
    "PKIRoleApplyDTO",
)
