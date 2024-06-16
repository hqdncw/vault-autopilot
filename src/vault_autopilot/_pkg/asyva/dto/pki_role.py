from typing import Literal, NotRequired, Sequence

from typing_extensions import TypedDict

from .issuer import KeyType

KeyUsageType = set[Literal["DigitalSignature", "KeyAgreement", "KeyEncipherment"]]
ExtKeyUsageType = set[
    Literal[
        "ServerAuth",
        "ClientAuth",
        "CodeSigning",
        "EmailProtection",
        "IPSECEndSystem",
        "IPSECTunnel",
        "IPSECUser",
        "TimeStamping",
        "OCSPSigning",
        "MicrosoftServerGatedCrypto",
        "NetscapeServerGatedCrypto",
        "MicrosoftCommercialCodeSigning",
        "MicrosoftKernelCodeSigning",
    ]
]


class PKIRoleNameField(TypedDict):
    name: str


class MountPathField(TypedDict):
    mount_path: str


class PKIRoleFields(TypedDict):
    issuer_ref: str
    ttl: NotRequired[int]
    max_ttl: NotRequired[int]
    allow_localhost: NotRequired[bool]
    allowed_domains: NotRequired[Sequence[str]]
    allowed_domains_template: NotRequired[bool]
    allow_bare_domains: NotRequired[bool]
    allow_subdomains: NotRequired[bool]
    allow_glob_domains: NotRequired[bool]
    allow_wildcard_certificates: NotRequired[bool]
    allow_any_name: NotRequired[bool]
    enforce_hostnames: NotRequired[bool]
    allow_ip_sans: NotRequired[bool]
    allowed_uri_sans: NotRequired[Sequence[str]]
    allowed_uri_sans_template: NotRequired[bool]
    allowed_other_sans: NotRequired[Sequence[str]]
    allowed_serial_numbers: NotRequired[Sequence[str]]
    server_flag: NotRequired[bool]
    client_flag: NotRequired[bool]
    code_signing_flag: NotRequired[bool]
    email_protection_flag: NotRequired[bool]
    key_type: NotRequired[KeyType]
    key_bits: NotRequired[int]
    signature_bits: NotRequired[int]
    use_pss: NotRequired[bool]
    key_usage: NotRequired[KeyUsageType]
    ext_key_usage: NotRequired[ExtKeyUsageType]
    ext_key_usage_oids: NotRequired[Sequence[str]]
    use_csr_common_name: NotRequired[bool]
    use_csr_sans: NotRequired[bool]
    ou: NotRequired[Sequence[str]]
    organization: NotRequired[Sequence[str]]
    country: NotRequired[Sequence[str]]
    locality: NotRequired[Sequence[str]]
    province: NotRequired[Sequence[str]]
    street_address: NotRequired[Sequence[str]]
    postal_code: NotRequired[Sequence[str]]
    generate_lease: NotRequired[bool]
    no_store: NotRequired[bool]
    require_cn: NotRequired[bool]
    policy_identifiers: NotRequired[set[str]]
    basic_constraints_valid_for_non_ca: NotRequired[bool]
    not_before_duration: NotRequired[int]
    not_after: NotRequired[str]
    cn_validations: NotRequired[set[str]]
    allowed_user_ids: NotRequired[Sequence[str]]
    allow_token_displayname: NotRequired[bool]


class PKIRoleCreateDTO(PKIRoleNameField, PKIRoleFields, MountPathField): ...


class PKIRoleReadDTO(PKIRoleNameField, MountPathField): ...
