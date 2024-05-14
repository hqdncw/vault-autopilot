from typing import Any, Literal, NotRequired

import pydantic
import pydantic_core
from typing_extensions import TypedDict, Unpack

__all__ = ("convert_errors", "model_dump", "model_dump_json")


CUSTOM_TYPES = {
    "dict_type": "mapping_type",
    "model_attributes_type": "mapping_type",
    "list_type": "sequence_type",
    "tuple_type": "sequence_type",
    "union_tag_invalid": "enum_value_out_of_range",
    "union_tag_not_found": "missing",
    "unexpected_keyword_argument": "extra_field",
}
CUSTOM_MESSAGES = {
    # https://docs.pydantic.dev/latest/errors/validation_errors/#model_type
    "extra_field": "Extra fields not allowed",
    "missing": "Field is required",
    "enum_value_out_of_range": "Input must be set to one of the following values: \
    {expected_tags}",
    "mapping_type": "Input must be a valid mapping",
    "sequence_type": "Input must be a valid sequence",
    "too_short": (
        "Sequence must have at least {min_length} item after validation, not "
        "{actual_length}"
    ),
}


def convert_errors(
    ex: pydantic.ValidationError,
    custom_messages: dict[str, str] = CUSTOM_MESSAGES,
    custom_types: dict[str, str] = CUSTOM_TYPES,
) -> list[pydantic_core.ErrorDetails]:
    new_errors: list[pydantic_core.ErrorDetails] = []
    for error in ex.errors(include_url=False):
        ctx = error.get("ctx")

        # Hacky solution to ensure valid locations for tagged unions in Pydantic
        # validation errors.
        if error["loc"][0:3] == ("auth", "token", "token"):
            error["loc"] = (error["loc"][0], *error["loc"][2:])
        if error["type"] in ("union_tag_not_found", "union_tag_invalid"):
            error["loc"] += (ctx["discriminator"].replace("'", ""),)  # type: ignore[index]

        if custom_type := custom_types.get(error["type"]):
            error["type"] = custom_type
        if custom_message := custom_messages.get(error["type"]):
            error["msg"] = custom_message.format(**ctx) if ctx else custom_message
        if ctx:
            # we don't want to show the context to the user
            del error["ctx"]

        new_errors.append(error)
    return new_errors


class AbstractDumpKwargs(TypedDict):
    include: NotRequired[Any]
    exclude: NotRequired[Any]
    by_alias: NotRequired[bool]
    exclude_unset: NotRequired[bool]
    exclude_defaults: NotRequired[bool]
    exclude_none: NotRequired[bool]
    round_trip: NotRequired[bool]
    warnings: NotRequired[bool]


class ModelDumpJsonKwargs(AbstractDumpKwargs):
    indent: NotRequired[int]


def model_dump_json(obj: Any, **kwargs: Unpack[ModelDumpJsonKwargs]) -> str:
    return pydantic.RootModel(obj).model_dump_json(**kwargs)


class ModelDumpKwargs(AbstractDumpKwargs):
    mode: NotRequired[Literal["json", "python"] | str]


def model_dump(obj: Any, **kwargs: Unpack[ModelDumpKwargs]) -> dict[Any, Any]:
    return pydantic.RootModel(obj).model_dump(**kwargs)
