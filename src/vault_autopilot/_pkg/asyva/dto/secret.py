from typing import Any, NotRequired

from typing_extensions import TypedDict


class KvV1SecretCreateDTO(TypedDict):
    path: str
    data: dict[str, Any]
    mount_path: str


class KvV2SecretCreateDTO(KvV1SecretCreateDTO):
    cas: NotRequired[int]


class SecretReadDTO(TypedDict):
    mount_path: str
    path: str


class SecretUpdateOrCreateMetadata(TypedDict):
    mount_path: str
    path: str
    max_versions: NotRequired[int]
    cas_required: NotRequired[bool]
    delete_version_after: NotRequired[str]
    custom_metadata: NotRequired[dict[str, str]]
