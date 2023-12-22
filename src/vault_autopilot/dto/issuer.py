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

    def absolute_path(self) -> str:
        return "/".join((self.spec["secret_engine"], self.spec["name"]))

    def isser_ref_absolute_path(self) -> str:
        assert "issuance_params" in self.spec, "Issuance params must not be null"
        return self.spec["issuance_params"]["issuer_ref"]
