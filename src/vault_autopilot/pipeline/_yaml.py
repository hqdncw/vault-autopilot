import asyncio
import logging
import reprlib
from dataclasses import dataclass
from typing import IO, Any, Iterator

import pydantic
import yaml

from .. import dto, exc, util

logger = logging.getLogger(__name__)


QueueType = asyncio.PriorityQueue[tuple[int, dto.BaseDTO]]

_SCHEMA_PRIORITY_MAP = {
    "PasswordPolicy": (dto.PasswordPolicyDTO, 0),
    "Password": (
        dto.PasswordDTO,
        1,
    ),
}


# class LineNumberLoader(yaml.SafeLoader):
#     def __init__(self, stream) -> None:  # type: ignore
#         super().__init__(stream)

#     def compose_document(self) -> Any:
#         # Drop the DOCUMENT-START event.
#         self.get_event()  # type: ignore

#         # Compose the root node.
#         node = self.compose_node(None, None)  # type: ignore

#         # Drop the DOCUMENT-END event.
#         self.get_event()  # type: ignore

#         # this prevents cleaning of anchors between documents in **one stream**
#         # self.anchors = {}
#         return node

#     def construct_object(self, node, deep=False):
#         obj = super().construct_object(node, deep=deep)
#         num = node.start_mark.line
#         self.locations[id(obj)] = isinstance(obj, dict) and num or num + 1
#         return obj


# def load_all(stream, Loader):
#     """
#     Parse all YAML documents in a stream
#     and produce corresponding Python objects.
#     """
#     loader = Loader(stream)
#     try:
#         while loader.check_data():
#             yield loader.get_data(), loader.locations
#     finally:
#         loader.dispose()


@dataclass(slots=True, frozen=True)
class YamlPipeline:
    """
    This pipeline is responsible for processing YAML manifests received from the
    specified binary output. It extracts data from these manifests and creates
    DTOs, which it then places in the queue with the appropriate priority.
    """

    # TODO: Create an intelligent loader for YAML files that prioritizes the
    #  reading of critical documents first, allowing for simultaneous execution of the
    #  pipeline and dispatcher processes. This micro-optimization will decrease average
    #  memory consumption and speed up the application runtime.

    # TODO: Implement a file-based queue modeled after
    #  tempfile.SpooledTemporaryFile to efficiently manage large datasets while
    #  avoiding memory overflow.

    queue: QueueType
    streamer: Iterator[IO[bytes]]

    async def execute(self) -> QueueType:
        logger.debug("pipelining started")

        for reader in self.streamer:
            try:
                for obj in yaml.load_all(reader, yaml.Loader):
                    await self._consume(obj, filename=reader.name)
            except yaml.error.MarkedYAMLError as ex:
                raise exc.ManifestValidationError(
                    str(ex), filename=str(reader.name)
                ) from ex

        logger.debug("pipelining finished")
        return self.queue

    async def _consume(self, obj: dict[str, Any], filename: str) -> None:
        if not isinstance(obj, dict) or (kind := obj.get("kind")) is None:
            raise exc.ManifestValidationError(
                "Mapping 'kind' is missing in %s" % reprlib.repr(obj),
                filename=filename,
            )

        if kind in _SCHEMA_PRIORITY_MAP.keys():
            schema, priority = _SCHEMA_PRIORITY_MAP[kind]
        else:
            raise exc.ManifestKindMismatchError(
                "Unsupported kind %r. Supported object kinds include: %s"
                % (kind, str(_SCHEMA_PRIORITY_MAP.keys())),
                filename=filename,
                provided_kind=kind,
            )

        try:
            data = schema(**obj)
        except pydantic.ValidationError as ex:
            # TODO: print the contents of a YAML file, highlighting any invalid
            #  lines.
            raise exc.ManifestValidationError(
                str(util.pydantic.convert_errors(ex)), filename=filename
            )

        await self._put(priority, data)

    async def _put(self, priority: int, obj: dto.BaseDTO) -> None:
        await self.queue.put((priority, obj))
        logger.debug("scheduled task %r" % obj)
