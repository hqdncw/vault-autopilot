import http
import logging
from dataclasses import dataclass
from typing import Any, Optional, cast

from .. import constants, exc
from . import base

logger = logging.getLogger(__name__)


@dataclass
class KvManager(base.BaseManager):
    async def create_or_update(
        self,
        path: str,
        data: dict[str, str],
        mount_path: str,
        cas: Optional[int] = None,
    ) -> None:
        params: dict[str, Any] = {"data": data}
        if cas is not None:
            params.update({"options": {"cas": cas}})

        async with self.new_session() as sess:
            resp = await sess.post(
                f"/v1/{mount_path}/data/{path}",
                json=params,
            )

        if resp.status == http.HTTPStatus.OK:
            return

        errors: list[str] = (await resp.json())["errors"]

        if constants.CAS_MISMATCH in errors:
            try:
                required_cas = await self.get_curr_version(
                    path="dq", mount_path=mount_path
                )
            except exc.InvalidPathError:
                required_cas = 0
            except Exception as ex:
                logger.debug(ex, exc_info=ex)
                required_cas = None

            raise exc.CASParameterMismatchError(
                secret_path="/".join((mount_path, path)),
                provided_cas=cas,
                required_cas=required_cas,
            )

        raise await exc.VaultAPIError.from_response(
            "failed to create/update a secret", resp
        )

    async def get_curr_version(self, path: str, mount_path: str) -> int:
        async with self.new_session() as sess:
            resp = await sess.get(
                f"/v1/{mount_path}/metadata/{path}",
            )

        if resp.status == http.HTTPStatus.OK:
            return cast(int, (await resp.json())["data"]["current_version"])

        raise await exc.VaultAPIError.from_response(
            "Failed to retrieve secret current version", resp
        )
