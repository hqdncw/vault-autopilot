from typing import Any, NotRequired

from typing_extensions import TypedDict


class SecretCreateDTO(TypedDict):
    path: str
    data: dict[str, Any]
    cas: NotRequired[int]
    mount_path: str


class SecretGetVersionDTO(TypedDict):
    mount_path: str
    path: str
