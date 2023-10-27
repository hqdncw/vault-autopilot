from typing import Any

import pydantic
import pydantic_core

CUSTOM_TYPES = {
    "model_type": "mapping_type",
    "dataclass_type": "mapping_type",
    "list_type": "sequence_type",
    "tuple_type": "sequence_type",
}
CUSTOM_MESSAGES = {
    # https://docs.pydantic.dev/latest/errors/validation_errors/#model_type
    "mapping_type": "Input should be a valid mapping",
    "sequence_type": "Input should be a valid sequence",
    "too_short": (
        "Sequence should have at least {min_length} item after validation, not "
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

        if custom_type := custom_types.get(error["type"]):
            error["type"] = custom_type
        if custom_message := custom_messages.get(error["type"]):
            error["msg"] = custom_message.format(**ctx) if ctx else custom_message
        if ctx:
            del error["ctx"]

        new_errors.append(error)
    return new_errors


def model_dump_json(obj: Any, **kwargs: Any) -> str:
    return pydantic.RootModel(obj).model_dump_json(**kwargs)


def model_dump(obj: Any, **kwargs: Any) -> dict[str, Any]:
    return pydantic.RootModel(obj).model_dump(**kwargs)  # type: ignore[no-any-return]
