from typing import Any

import pydantic
import pydantic.alias_generators
from pydantic.dataclasses import dataclass
from typing_extensions import TypedDict

base_model_config = pydantic.ConfigDict(
    alias_generator=pydantic.alias_generators.to_camel
)


class SecretEngineMixin(TypedDict):
    secret_engine: str


class PathMixin(TypedDict):
    path: str


@dataclass(config=base_model_config)
class BaseDTO:
    def __lt__(self, other: Any) -> bool:
        if isinstance(other, BaseDTO):
            # dirty-hack to retrieve items from priority queue
            return False
        raise TypeError()


__all__ = [
    "base_model_config",
    "SecretEngineMixin",
    "PathMixin",
    "BaseDTO",
]
