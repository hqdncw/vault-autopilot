from typing import Literal, NotRequired, Sequence

from typing_extensions import TypedDict

ListingVisibilityType = Literal["unauth", "hidden"]


class KvV2Options(TypedDict):
    version: NotRequired[str]


class MountPathField(TypedDict):
    secret_mount_path: str


class SecretsEngineCommonFields(TypedDict):
    default_lease_ttl: NotRequired[int]
    max_lease_ttl: NotRequired[int]
    audit_non_hmac_request_keys: NotRequired[Sequence[str]]
    audit_non_hmac_response_keys: NotRequired[Sequence[str]]
    listing_visibility: NotRequired[ListingVisibilityType]
    passthrough_request_headers: NotRequired[Sequence[str]]
    allowed_response_headers: NotRequired[Sequence[str]]
    allowed_managed_keys: NotRequired[Sequence[str]]
    plugin_version: NotRequired[str]
    delegated_auth_accessors: NotRequired[Sequence[str]]


class SecretsEngineConfig(SecretsEngineCommonFields):
    identity_token_key: NotRequired[str]
    force_no_cache: NotRequired[bool]


class SecretsEngineEnableDTO(TypedDict):
    path: str
    type: str
    description: NotRequired[str]
    config: NotRequired[SecretsEngineConfig]
    options: NotRequired[KvV2Options]
    local: NotRequired[bool]
    seal_wrap: NotRequired[bool]
    external_entropy_access: NotRequired[bool]


class SecretsEngineConfigureDTO(MountPathField):
    cas_required: NotRequired[bool]
    delete_version_after: NotRequired[str]
    max_versions: NotRequired[int]


class SecretsEngineTuneMountConfigurationDTO(SecretsEngineCommonFields):
    path: str
    description: NotRequired[str]


class SecretsEngineReadDTO(TypedDict):
    path: str
