import pydantic
import pydantic_core

CUSTOM_MESSAGES = {
    # https://docs.pydantic.dev/latest/errors/validation_errors/#model_type
    "model_type": "Input should be a valid YAML mapping",
    "dataclass_type": "Input should be a valid YAML mapping",
}


def convert_errors(
    ex: pydantic.ValidationError, custom_messages: dict[str, str] = CUSTOM_MESSAGES
) -> list[pydantic_core.ErrorDetails]:
    new_errors: list[pydantic_core.ErrorDetails] = []
    for error in ex.errors(include_url=False, include_context=False):
        custom_message = custom_messages.get(error["type"])
        if custom_message:
            ctx = error.get("ctx")
            error["msg"] = custom_message.format(**ctx) if ctx else custom_message
        new_errors.append(error)
    return new_errors
