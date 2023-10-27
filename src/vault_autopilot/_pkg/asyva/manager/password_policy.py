import http
import logging
from dataclasses import dataclass
from typing import cast

from typing_extensions import Unpack

from .. import dto, exc
from . import base

logger = logging.getLogger(__name__)


BASE_PATH = "/v1/sys/policies/password"


@dataclass
class PasswordPolicyManager(base.BaseManager):
    async def create_or_update(
        self, **payload: Unpack[dto.PasswordPolicyCreateDTO]
    ) -> None:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/".join((BASE_PATH, payload["path"])),
                json={"policy": payload["policy"]},
            )

        if resp.status == http.HTTPStatus.NO_CONTENT:
            return

        logger.debug(await resp.json())
        raise await exc.VaultAPIError.from_response(
            "Failed to create password policy", resp
        )

    async def generate_password(
        self, **payload: Unpack[dto.PasswordPolicyGenerateDTO]
    ) -> str:
        async with self.new_session() as sess:
            resp = await sess.get(
                "/".join((BASE_PATH, payload["policy_path"], "generate"))
            )

        resp_body = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return cast(str, resp_body["data"]["password"])
        elif resp.status == http.HTTPStatus.NOT_FOUND:
            raise exc.PasswordPolicyNotFoundError(
                "Failed to generate a password, password policy {policy_name!r} not "
                "found",
                policy_name=payload["policy_path"],
            )

        logger.debug(resp_body)
        raise await exc.VaultAPIError.from_response(
            "Failed to generate a password", resp
        )
