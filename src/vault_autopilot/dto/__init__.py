from typing import Union

from .issuer import IssuerCreateDTO
from .password import PasswordCreateDTO
from .password_policy import PasswordPolicyCreateDTO

DTO = Union[IssuerCreateDTO, PasswordCreateDTO, PasswordPolicyCreateDTO]

__all__ = (
    "DTO",
    "IssuerCreateDTO",
    "PasswordCreateDTO",
    "PasswordPolicyCreateDTO",
)
