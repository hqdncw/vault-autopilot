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
class IssuerDTO(base.BaseDTO):
    spec: IssuerSpec
