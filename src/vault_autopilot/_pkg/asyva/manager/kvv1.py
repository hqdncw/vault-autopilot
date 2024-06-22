import logging
from http import HTTPStatus
from os import path

from typing_extensions import Any, Unpack

from .. import dto
from ..exc import (
    VaultAPIError,
)
from .base import AbstractResult, BaseManager

logger = logging.getLogger(__name__)


class ReadResult(AbstractResult):
    data: dict[Any, Any]


class KvV1Manager(BaseManager):
    async def update_or_create(
        self, **payload: Unpack[dto.KvV1SecretCreateDTO]
    ) -> None:
        """
        References:
            <https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#read-secret>
        """

        async with self.new_session() as sess:
            resp = await sess.post(
                url=path.join("/v1", payload["mount_path"], payload["path"]),
                json=payload["data"],
            )

        if resp.status == HTTPStatus.NO_CONTENT:
            return

        raise await VaultAPIError.from_response("Failed to update/create secret", resp)

    async def read(self, **payload: Unpack[dto.SecretReadDTO]) -> ReadResult | None:
        """
        References:
            <https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#read-secret>
        """

        async with self.new_session() as sess:
            resp = await sess.get(
                url=path.join("/v1", payload["mount_path"], payload["path"]),
            )

        if resp.status == HTTPStatus.OK:
            return ReadResult.from_response(await resp.json())

        if resp.status == HTTPStatus.NOT_FOUND:
            return None

        raise await VaultAPIError.from_response("Failed to update/create secret", resp)
