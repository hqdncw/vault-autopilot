from pydantic.dataclasses import dataclass
from typing_extensions import NotRequired, TypedDict

from .._pkg.asyva.dto import issuer
from . import base


class CSRParams(issuer.CACommonFieldsMixin, issuer.CAKeyGenerationMixin):
    issuer_name: str
    add_basic_constraints: NotRequired[bool]
    # TODO: Make `managed_*` fields exclusive
    managed_key_name: NotRequired[str]
    managed_key_id: NotRequired[str]


class IssuerRef(base.SecretEngineMixin):
    issuer_name: str


class IssuanceParams(TypedDict):
    issuer_ref: IssuerRef
    signature_bits: NotRequired[int]
    skid: NotRequired[str]
    use_pss: NotRequired[bool]


class IssuerSpec(base.SecretEngineMixin):
    csr_params: CSRParams
    issuance_params: NotRequired[IssuanceParams]


@dataclass(slots=True)
class IssuerCreateDTO(base.BaseDTO):
    spec: IssuerSpec

    def get_full_path(self) -> str:
        return "{0[secret_engine]}/{0[csr_params][issuer_name]}".format(self.spec)

    def get_issuing_authority_full_path(self) -> str:
        """
        Retrieves the unique identifier (UID) of the issuer that issued this issuer. In
        other words, this method returns the UID of the issuer that signed the
        certificate contains the public key of this issuer.
        """
        iss_params = self.spec.get("issuance_params")
        assert isinstance(iss_params, dict), "Issuance params must not be null"
        return "{0[secret_engine]}/{0[issuer_name]}".format(iss_params["issuer_ref"])

    def __hash__(self) -> int:
        return hash(self.get_full_path())
