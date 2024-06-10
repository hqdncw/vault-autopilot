import asyncio
import logging
import pathlib
from collections.abc import Generator, Iterator
from dataclasses import dataclass
from typing import IO, Any, Generic, TypeVar

import ruamel.yaml as yaml
from pydantic import ConfigDict, RootModel, ValidationError
from pydantic.alias_generators import to_camel
from ruamel.yaml.error import YAMLError

from vault_autopilot.exc import ManifestSyntaxError, ManifestValidationError

from . import util

__all__ = ("ManifestParser",)

T = TypeVar("T", bound="AbstractManifestObject")  # type: ignore

logger = logging.getLogger(__name__)
loader = yaml.YAML(typ="rt")


class AbstractManifestObject(RootModel[T]):
    model_config = ConfigDict(alias_generator=to_camel)

    root: Any


@dataclass(slots=True)
class ManifestParser(Generic[T]):
    """
    A generic parser for manifest files.

    This class provides a generic implementation for parsing manifest files and
    converting them into specific object types. It utilizes an iterator to process
    multiple manifest files and a queue to manage the parsed objects.

    Attributes:
        manifest_iterator: An iterator yielding open file objects containing the
            manifest data in bytes.
        object_builder: The class type of the desired output objects.
        queue: A queue to store the parsed objects.

    Raises:
        ManifestSyntaxError: Raised when there is a syntax error in the manifest file.
        ManifestValidationError: Raised when the parsed data fails model validation.

    Example::

        import asyncio
        from vault_autopilot.parser import AbstractManifestObject, ManifestParser

        # Define your manifest files and object class
        manifest_files = [open("/path/to/file", "rb")]
        MyObject = AbstractManifestObject

        # Create a ManifestParser instance
        parser = ManifestParser[MyObject](
            manifest_iterator=iter(manifest_files),
            object_builder=MyObject,
            queue=asyncio.Queue(),
        )

        # Start parsing and processing the manifest files
        await parser.execute()

        # Access the parsed objects from the queue
        print(await parser.queue.get())
    """

    # TODO: Implement a file-based queue modeled after
    #  tempfile.SpooledTemporaryFile to efficiently manage large datasets while
    #  avoiding memory overflow.

    manifest_iterator: Iterator[IO[bytes]]
    object_builder: type[T]
    queue: asyncio.Queue[T | None]

    async def execute(self) -> asyncio.Queue[T | None]:
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

                try:
                    payload = self.object_builder.model_validate(payload)
                except ValidationError as ex:
                    raise ManifestValidationError(
                        str(util.model.convert_errors(ex)),
                        ManifestValidationError.Context(
                            loc={"filename": pathlib.Path(fn)}
                        ),
                    )

                logger.debug("parsed %r", payload)
                await self.queue.put(payload)

        logger.debug("parsed files successfully")
        await self.queue.put(None)

        return self.queue
