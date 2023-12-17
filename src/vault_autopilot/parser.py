import asyncio
import logging
import pathlib
from dataclasses import dataclass
from typing import IO, Any, Iterator

import pydantic
import pydantic.alias_generators
import ruamel.yaml as yaml
from ruamel.yaml.error import YAMLError

from . import dto, exc, util

__all__ = ("QueueType", "EndByte", "ManifestParser")


QueueType = asyncio.Queue["dto.DTO | EndByte"]

logger = logging.getLogger(__name__)

KIND_SCHEMA_MAP: dict[str, pydantic.TypeAdapter[dto.DTO]] = {
    "Password": pydantic.TypeAdapter(dto.PasswordCreateDTO),
    "Issuer": pydantic.TypeAdapter(dto.IssuerCreateDTO),
    "PasswordPolicy": pydantic.TypeAdapter(dto.PasswordPolicyCreateDTO),
}
loader = yaml.YAML(typ="rt")


class EndByte:
    """Indicates that the parser has finished parsing."""


@dataclass(slots=True)
class ManifestParser:
    """
    Processes YAML manifests obtained from the `manifest_iterator`, extracting data and
    creating DTO objects before placing them in a FIFO queue.
    """

    # TODO: Implement a file-based queue modeled after
    #  tempfile.SpooledTemporaryFile to efficiently manage large datasets while
    #  avoiding memory overflow.

    queue: "QueueType"
    manifest_iterator: Iterator[IO[bytes]]

    async def execute(self) -> "QueueType":
        logger.debug("parsing files started")

        def stream_documents(buf: IO[bytes]) -> Any:
            return (obj for obj in loader.load_all(buf))

        for buf in self.manifest_iterator:
            iter_, fn = stream_documents(buf), buf.name

            while True:
                try:
                    payload = next(iter_)
                except YAMLError as ex:
                    raise exc.ManifestSyntaxError(
                        str(ex),
                        exc.ManifestSyntaxError.Context(filename=pathlib.Path(fn)),
                    ) from ex
                except StopIteration:
                    break
                else:
                    ctx = exc.ManifestValidationError.Context(filename=pathlib.Path(fn))

                    if (
                        not isinstance(payload, dict)
                        or (kind := payload.get("kind")) is None
                    ):
                        raise exc.ManifestValidationError(
                            "Mapping 'kind' is missing in %r" % payload,
                            ctx,
                        )

                    if kind in KIND_SCHEMA_MAP.keys():
                        schema = KIND_SCHEMA_MAP[kind]
                    else:
                        raise exc.ManifestValidationError(
                            "Unsupported kind %r. Supported object kinds include: %s"
                            % (kind, tuple(KIND_SCHEMA_MAP.keys())),
                            ctx,
                        )

                    try:
                        payload = schema.validate_python(payload)
                    except pydantic.ValidationError as ex:
                        raise exc.ManifestValidationError(
                            str(util.model.convert_errors(ex)), ctx
                        )

                    logger.debug("put %r", payload)
                    await self.queue.put(payload)

        logger.debug("parsing files finished")
        await self.queue.put(EndByte())

        return self.queue
