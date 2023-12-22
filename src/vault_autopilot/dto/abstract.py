import pydantic.alias_generators
from pydantic import BaseModel, ConfigDict


class AbstractDTO(BaseModel):
    model_config = ConfigDict(
        alias_generator=pydantic.alias_generators.to_camel, extra="forbid"
    )
