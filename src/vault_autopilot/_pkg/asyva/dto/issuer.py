from typing import Literal, NotRequired

from typing_extensions import TypedDict

IssuerType = Literal["root", "intermediate"]
IssuerCertType = Literal["internal", "exported", "existing", "kms"]
KeyType = Literal["rsa", "ed25519", "ec"]
LeafNotAfterBehaviorType = Literal["err", "truncate", "permit"]
SignatureAlgorithmType = Literal[
    "MD5WithRSA",
    "SHA1WithRSA",
    "SHA256WithRSA",
    "SHA384WithRSA",
    "SHA512WithRSA",
    "ECDSAWithSHA1",
    "ECDSAWithSHA256",
    "ECDSAWithSHA384",
    "ECDSAWithSHA512",
    "SHA256WithRSAPSS",
    "SHA384WithRSAPSS",
    "SHA512WithRSAPSS",
    "PureEd25519",
]


class CommonFields(TypedDict):
    common_name: str
    alt_names: NotRequired[str]
    ip_sans: NotRequired[str]
    uri_sans: NotRequired[str]
    other_sans: NotRequired[str]
    ttl: NotRequired[str]
    max_path_length: NotRequired[int]
    exclude_cn_from_sans: NotRequired[bool]
    permitted_dns_domains: NotRequired[str]
    ou: NotRequired[str]
    organization: NotRequired[str]
    country: NotRequired[str]
    locality: NotRequired[str]
    province: NotRequired[str]
    street_address: NotRequired[str]
    postal_code: NotRequired[str]
    serial_number: NotRequired[str]
    not_before_duration: NotRequired[str]
    not_after: NotRequired[str]


class KeyGenerationFields(TypedDict):
    type: IssuerCertType
    key_name: NotRequired[str]
    key_ref: NotRequired[str]
    key_type: NotRequired[KeyType]
    key_bits: NotRequired[int]


class ManagedKeyFields(TypedDict):
    managed_key_name: NotRequired[str]
    managed_key_id: NotRequired[str]


class MountPathField(TypedDict):
    mount_path: str


class IssuerNameField(TypedDict):
    issuer_name: NotRequired[str]


class IssuerRefField(TypedDict):
    issuer_ref: str


class IssuerMutableFields(TypedDict):
    leaf_not_after_behavior: NotRequired[LeafNotAfterBehaviorType]
    manual_chain: NotRequired[tuple[str]]
    usage: NotRequired[str]
    revocation_signature_algorithm: NotRequired[SignatureAlgorithmType]
    issuing_certificates: NotRequired[tuple[str]]
    crl_distribution_points: NotRequired[tuple[str]]
    ocsp_servers: NotRequired[tuple[str]]
    enable_aia_url_templating: NotRequired[bool]


class IssuerGenerateRootDTO(
    CommonFields, KeyGenerationFields, ManagedKeyFields, MountPathField, IssuerNameField
):
    pass


class IssuerGenerateIntmdCSRDTO(
    CommonFields, KeyGenerationFields, ManagedKeyFields, MountPathField
):
    add_basic_constraints: NotRequired[bool]


class IssuerSignIntmdDTO(CommonFields, MountPathField, IssuerRefField):
    csr: str
    use_csr_values: NotRequired[bool]
    signature_bits: NotRequired[int]
    skid: NotRequired[str]
    use_pss: NotRequired[bool]


class IssuerUpdateDTO(
    MountPathField, IssuerNameField, IssuerRefField, IssuerMutableFields
):
    pass


class IssuerSetSignedIntmdDTO(MountPathField):
    certificate: str


class IssuerReadDTO(MountPathField, IssuerRefField): ...


class KeyUpdateDTO(MountPathField):
    key_ref: str
    key_name: str
