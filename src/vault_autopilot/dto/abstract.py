import pydantic.alias_generators
from typing_extensions import TypedDict


class AbstractDTO(TypedDict):
    __pydantic_config__ = pydantic.ConfigDict(  # type: ignore[misc]
        alias_generator=pydantic.alias_generators.to_camel, extra="forbid"
    )
