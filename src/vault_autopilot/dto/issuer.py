from typing import Literal, NotRequired

from typing_extensions import TypedDict

from .._pkg.asyva.dto import issuer
from . import abstract


class CSRParams(
    issuer.CommonFields, issuer.KeyGenerationFields, issuer.ManagedKeyFields
):
    # TODO: Allow to set `add_basic_constraints` only when the issuer is intermediate
    add_basic_constraints: NotRequired[bool]


class IssuanceParams(TypedDict):
    issuer_ref: str
    signature_bits: NotRequired[int]
    skid: NotRequired[str]
    use_pss: NotRequired[bool]


class IssuerSpec(TypedDict):
    name: str
    secret_engine: str
    csr_params: CSRParams
    issuance_params: NotRequired[IssuanceParams]


class IssuerCreateDTO(abstract.AbstractDTO):
    kind: Literal["Issuer"]
    spec: IssuerSpec
