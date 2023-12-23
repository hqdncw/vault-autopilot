from typing import Union

from .issuer import IssuerInitializeDTO
from .password import PasswordInitializeDTO
from .password_policy import PasswordPolicyInitializeDTO

DTO = Union[IssuerInitializeDTO, PasswordInitializeDTO, PasswordPolicyInitializeDTO]

__all__ = (
    "DTO",
    "IssuerInitializeDTO",
    "PasswordInitializeDTO",
    "PasswordPolicyInitializeDTO",
)
