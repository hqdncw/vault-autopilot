import http
import logging
from dataclasses import dataclass
from typing import Any, cast

from typing_extensions import Unpack

from .... import util
from .. import constants, dto, exc
from . import base

logger = logging.getLogger(__name__)

SECRET_EXCL = {"mount_path", "path"}


@dataclass
class KVV2Manager(base.BaseManager):
    async def create_or_update(self, **payload: Unpack[dto.SecretCreateDTO]) -> None:
        data: dict[str, Any] = dict(
            data=util.pydantic.model_dump(
                payload, exclude=SECRET_EXCL, exclude_unset=True
            )
        )
        if isinstance((cas := payload.get("cas")), int):
            data.update(dict(options=dict(cas=cas)))

        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/{0[mount_path]}/data/{0[path]}".format(payload),
                json=data,
            )

        if resp.status == http.HTTPStatus.OK:
            return

        resp_body = await resp.json()
        if constants.CAS_MISMATCH in resp_body["errors"]:
            mount_path, path = payload["mount_path"], payload["path"]

            try:
                required_cas = await self.get_version(path=path, mount_path=mount_path)
            except exc.InvalidPathError:
                required_cas = 0
            except Exception as ex:
                logger.debug(ex, exc_info=ex)
                required_cas = None

            raise exc.CASParameterMismatchError(
                message=(
                    "Failed to push secret (path: {secret_path!r}): CAS mismatch "
                    "(expected {required_cas!r}, got {provided_cas!r}). Ensure correct "
                    "CAS value and try again"
                ),
                secret_path="/".join((mount_path, path)),
                provided_cas=cas,
                required_cas=required_cas,
            )

        logger.debug(resp_body)
        raise await exc.VaultAPIError.from_response(
            "failed to create/update secret", resp
        )

    async def get_version(self, **payload: Unpack[dto.SecretGetVersionDTO]) -> int:
        async with self.new_session() as sess:
            resp = await sess.get(
                "/v1/{0[mount_path]}/metadata/{0[path]}".format(payload)
            )

        resp_body = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return cast(int, resp_body["data"]["current_version"])

        logger.debug(resp_body)
        raise await exc.VaultAPIError.from_response(
            "Failed to retrieve secret current version", resp
        )
