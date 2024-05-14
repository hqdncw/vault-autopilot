import asyncio
import logging
import pathlib
from dataclasses import dataclass
from typing import IO
from collections.abc import Generator, Iterator
from typing import Any

import pydantic
import pydantic.alias_generators
import ruamel.yaml as yaml
from ruamel.yaml.error import YAMLError

from .exc import ManifestSyntaxError

from . import dto, util

__all__ = ("QueueType", "ManifestParser")


QueueType = asyncio.Queue[dto.DTO | None]

logger = logging.getLogger(__name__)

KIND_SCHEMA_MAP: dict[str, type[dto.DTO]] = {
    "Password": dto.PasswordApplyDTO,
    "Issuer": dto.IssuerApplyDTO,
    "PasswordPolicy": dto.PasswordPolicyApplyDTO,
    "PKIRole": dto.PKIRoleApplyDTO,
}

loader = yaml.YAML(typ="rt")


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
        logger.debug("parsing files")

        def stream_documents(buf: IO[bytes]) -> Generator[Any, Any, Any]:
            return (obj for obj in loader.load_all(buf))

        for buf in self.manifest_iterator:
            iter_, fn = stream_documents(buf), buf.name

            while True:
                try:
                    payload = next(iter_)
                except YAMLError as ex:
                    raise ManifestSyntaxError(
                        str(ex),
                        ManifestSyntaxError.Context(loc={"filename": pathlib.Path(fn)}),
                    ) from ex
                except StopIteration:
                    break
                else:
                    ctx = ManifestSyntaxError.Context(
                        loc={"filename": pathlib.Path(fn)}
                    )

                    if (
                        not isinstance(payload, dict)
                        or (kind := payload.get("kind")) is None
                    ):
                        raise ManifestSyntaxError(
                            "Mapping 'kind' is missing in %r" % payload,
                            ctx,
                        )

                    if kind in KIND_SCHEMA_MAP.keys():
                        schema = KIND_SCHEMA_MAP[kind]
                    else:
                        raise ManifestSyntaxError(
                            "Unsupported kind %r. Supported object kinds include: %s"
                            % (kind, tuple(KIND_SCHEMA_MAP.keys())),
                            ctx,
                        )

                    try:
                        payload = schema.model_validate(payload)
                    except pydantic.ValidationError as ex:
                        raise ManifestSyntaxError(
                            str(util.model.convert_errors(ex)), ctx
                        )

                    logger.debug("put %r", payload)
                    await self.queue.put(payload)

        logger.debug("parsed files successfully")
        await self.queue.put(None)

        return self.queue
