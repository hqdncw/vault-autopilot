import http
from typing import cast

from ..exc import PasswordPolicyNotFoundError, VaultAPIError
from . import base

BASE_PATH = "/v1/sys/policies/password"


class PasswordPolicyManager(base.BaseManager):
    async def update_or_create(self, path: str, policy: str) -> None:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/".join((BASE_PATH, path)),
                json={"policy": policy},
            )

        if resp.status == http.HTTPStatus.NO_CONTENT:
            return

        raise await VaultAPIError.from_response(
            "Failed to create password policy", resp
        )

    async def generate_password(self, policy_path: str) -> str:
        async with self.new_session() as sess:
            resp = await sess.get("/".join((BASE_PATH, policy_path, "generate")))

        resp_body = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return cast(str, resp_body["data"]["password"])
        elif resp.status == http.HTTPStatus.NOT_FOUND:
            raise PasswordPolicyNotFoundError(
                "Failed to generate a password, password policy "
                "{ctx[path]!r} not found",
                ctx=PasswordPolicyNotFoundError.Context(
                    **await VaultAPIError.compose_context(resp),
                    path=policy_path,
                    mount_path=BASE_PATH,
                ),
            )

        raise await VaultAPIError.from_response("Failed to generate a password", resp)
