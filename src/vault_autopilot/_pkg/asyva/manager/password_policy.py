import http
import logging
from dataclasses import dataclass
from typing import IO, cast

from .... import util
from .. import exc
from . import base

logger = logging.getLogger(__name__)


BASE_PATH = "/v1/sys/policies/password/"


@dataclass
class PasswordPolicyManager(base.BaseManager):
    async def create_or_update(
        self,
        path: str,
        policy: IO[str],
    ) -> None:
        async with self.new_session() as sess:
            resp = await sess.post(
                "".join((BASE_PATH, path)),
                json={"policy": util.encoding.base64_encode("".join(policy))},
            )

        if resp.status == http.HTTPStatus.NO_CONTENT:
            return

        raise await exc.VaultAPIError.from_response(
            "Failed to create a password policy", resp
        )

    async def generate(self, path: str) -> str:
        async with self.new_session() as sess:
            resp = await sess.get("".join((BASE_PATH, path, "/generate")))

        if resp.status == http.HTTPStatus.OK:
            return cast(str, (await resp.json())["data"]["password"])
        elif resp.status == http.HTTPStatus.NOT_FOUND:
            raise exc.PolicyNotFoundError(
                "Failed to generate a password, policy %r not found"
                % "".join((BASE_PATH, path))
            )

        raise await exc.VaultAPIError.from_response(
            "Failed to generate a password", resp
        )
