from typing import Union

from .issuer import IssuerCheckOrSetDTO
from .password import PasswordCheckOrSetDTO
from .password_policy import PasswordPolicyCheckOrSetDTO
from .pki_role import PKIRoleCheckOrSetDTO

DTO = Union[
    IssuerCheckOrSetDTO,
    PasswordCheckOrSetDTO,
    PasswordPolicyCheckOrSetDTO,
    PKIRoleCheckOrSetDTO,
]

__all__ = (
    "DTO",
    "IssuerCheckOrSetDTO",
    "PasswordCheckOrSetDTO",
    "PasswordPolicyCheckOrSetDTO",
    "PKIRoleCheckOrSetDTO",
)
