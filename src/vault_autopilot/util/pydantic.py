import pydantic
import pydantic_core

CUSTOM_MESSAGES = {
    # https://docs.pydantic.dev/latest/errors/validation_errors/#model_type
    "model_type": "Input should be a valid mapping",
    "dataclass_type": "Input should be a valid mapping",
    "list_type": "Input should be a valid sequence",
    "too_short": (
        "Sequence should have at least {min_length} item after validation, not "
        "{actual_length}"
    ),
}


def convert_errors(
    ex: pydantic.ValidationError, custom_messages: dict[str, str] = CUSTOM_MESSAGES
) -> list[pydantic_core.ErrorDetails]:
    new_errors: list[pydantic_core.ErrorDetails] = []
    for error in ex.errors(include_url=False):
        custom_message, ctx = custom_messages.get(error["type"]), error.get("ctx")
        if custom_message:
            error["msg"] = custom_message.format(**ctx) if ctx else custom_message
        if ctx:
            del error["ctx"]
        new_errors.append(error)
    return new_errors
