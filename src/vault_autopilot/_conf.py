from typing import Annotated, Literal

from pydantic import ConfigDict, Field
from pydantic.alias_generators import to_camel
from pydantic.dataclasses import dataclass
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from typing_extensions import TypedDict

from ._pkg import asyva

_config = ConfigDict(alias_generator=to_camel, extra="forbid")


@dataclass(slots=True, config=_config, kw_only=True)
class KubernetesAuthMethod(asyva.KubernetesAuthenticator):
    method: Literal["kubernetes"]


@dataclass(slots=True, config=_config, kw_only=True)
class TokenAuthMethod(asyva.TokenAuthenticator):
    method: Literal["token"]


class VaultSecretStorage(TypedDict):
    type: Literal["kvv1-secret"]
    secrets_engine_path: Annotated[
        str, Field(default="hqdncw.github.io/vault-autopilot/user-data")
    ]
    snapshots_secret_path: Annotated[str, Field(default="snapshots")]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        alias_generator=to_camel,
        extra="forbid",
        validate_default=False,
        env_nested_delimiter="__",
    )

    base_url: str
    storage: VaultSecretStorage
    auth: KubernetesAuthMethod | TokenAuthMethod = Field(discriminator="method")
    default_namespace: str = ""

    @classmethod
    def settings_customise_sources(
        cls,
        _: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return env_settings, file_secret_settings, init_settings
