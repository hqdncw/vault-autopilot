from typing import Union

from .issuer import IssuerApplyDTO, IssuerGetDTO
from .password import PasswordApplyDTO
from .password_policy import PasswordPolicyApplyDTO
from .pki_role import PKIRoleApplyDTO
from .secrets_engine import SecretsEngineApplyDTO

DTO = Union[
    IssuerApplyDTO,
    PasswordApplyDTO,
    PasswordPolicyApplyDTO,
    PKIRoleApplyDTO,
]

__all__ = (
    "DTO",
    "IssuerApplyDTO",
    "IssuerGetDTO",
    "PasswordApplyDTO",
    "PasswordPolicyApplyDTO",
    "PKIRoleApplyDTO",
    "SecretsEngineApplyDTO",
)
