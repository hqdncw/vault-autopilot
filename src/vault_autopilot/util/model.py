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
    "enum_value_out_of_range": (
        "Input must be set to one of the following values: {expected_tags}"
    ),
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

    # /*
    # Oh, Great and Powerful Jesus Christ,
    # Please bless this dirty hack with your divine guidance.
    # May it work as intended, despite its questionable nature.
    # Let it be a testament to our resourcefulness and ingenuity.
    # And should it break, let it do so in the most spectacular and entertaining way
    # possible.
    # Amen.
    # */

    for error in ex.errors(include_url=False):
        ctx = error.get("ctx")

        try:
            field = error["loc"][0]
        except IndexError:
            pass
        else:
            if field in (
                "Password",
                "PasswordPolicy",
                "SecretsEngine",
                "PKIRole",
                "Issuer",
            ):
                error["loc"] = error["loc"][1:]

        # Ensure valid locations for tagged unions in Pydantic validation errors

        # SecretsEngine
        if error["loc"][0:3] in (
            ("spec", "engine", "kv-v2"),
            ("spec", "engine", "pki"),
        ):
            error["loc"] = (*error["loc"][:2], *error["loc"][3:])
        else:
            # Configuration file
            # 'loc': ('auth', 'token', 'token'), => ('auth', "token"),
            if error["loc"][0:3] == ("auth", "token", "token"):
                error["loc"] = (error["loc"][0], *error["loc"][2:])
            # 'loc': ('auth',), => ('auth', "method"),
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


def recursive_dict_filter(dict1: Any, dict2: Any) -> dict[Any, Any]:
    """
    Example::

        dict1 = {'a': 1, 'b': 2, 'c': {'d': 3, 'e': 4}, 'f': 5}
        dict2 = {'a': 1, 'c': {'d': 3}}

        result = recursive_dict_filter(dict1, dict2)

        print(result)  # Output: {'a': 1, 'c': {'d': 3}}
    """
    result = {}
    for k, v in dict1.items():
        if k in dict2:
            if isinstance(v, dict):
                result[k] = recursive_dict_filter(v, dict2.get(k, {}))
            else:
                result[k] = v
    return result
