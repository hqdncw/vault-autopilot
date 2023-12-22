import http
import logging
from typing import cast

from .. import constants, dto, exc
from . import base

logger = logging.getLogger(__name__)


class KVV2Manager(base.BaseManager):
    async def create_or_update(self, payload: dto.SecretCreateDTO) -> None:
        """
        References:
            https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#create-update-secret
        """
        data, mount_path, path = (
            {"data": payload["data"]},
            payload["mount_path"],
            payload["path"],
        )

        if isinstance((cas := payload.get("cas")), int):
            data.update({"options": {"cas": cas}})

        async with self.new_session() as sess:
            resp = await sess.post("/v1/%s/data/%s" % (mount_path, path), json=data)

        if resp.status == http.HTTPStatus.OK:
            return

        result = await resp.json()
        logger.debug(result)
        if constants.CAS_MISMATCH in result["errors"]:
            ctx = exc.CASParameterMismatchError.Context(
                secret_path="/".join((mount_path, path))
            )

            if cas is not None:
                ctx.update({"provided_cas": cas})

            try:
                ctx.update(
                    {
                        "required_cas": await self.get_version(
                            dto.SecretGetVersionDTO(mount_path=mount_path, path=path)
                        )
                    }
                )
            except exc.InvalidPathError:
                ctx.update({"required_cas": 0})
            except exc.VaultAPIError as ex:
                logger.debug("Failed to fetch the required cas value", exc_info=ex)

            raise exc.CASParameterMismatchError(
                message=(
                    "Failed to push secret (path: {secret_path!r}): CAS mismatch "
                    "(expected {required_cas!r}, got {provided_cas!r}). Ensure correct "
                    "CAS value and try again"
                ),
                ctx=ctx,
            )

        raise await exc.VaultAPIError.from_response(
            "Failed to create/update secret", resp
        )

    async def get_version(self, payload: dto.SecretGetVersionDTO) -> int:
        async with self.new_session() as sess:
            resp = await sess.get(
                "/v1/%s/metadata/%s" % (payload["mount_path"], payload["path"])
            )

        result = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return cast(int, result["data"]["current_version"])

        raise await exc.VaultAPIError.from_response(
            "Failed to retrieve secret current version", resp
        )
