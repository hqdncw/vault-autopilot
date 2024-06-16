from http import HTTPStatus
from typing import cast

from typing_extensions import TypedDict

from ...._pkg.asyva.manager.base import AbstractResult, BaseManager
from .. import constants
from ..exc import PasswordPolicyNotFoundError, VaultAPIError

BASE_PATH = "/v1/sys/policies/password"


class ReadResult(AbstractResult):
    class Data(TypedDict):
        policy: str

    data: Data


class PasswordPolicyManager(BaseManager):
    async def update_or_create(self, path: str, policy: str) -> None:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/".join((BASE_PATH, path)),
                json={"policy": policy},
            )

        if resp.status == HTTPStatus.NO_CONTENT:
            return

        raise await VaultAPIError.from_response(
            "Failed to create password policy", resp
        )

    async def read(self, path: str) -> ReadResult | None:
        async with self.new_session() as sess:
            resp = await sess.get("/".join((BASE_PATH, path)))

        result = await resp.json() or {}

        if resp.status == HTTPStatus.OK:
            return ReadResult.from_response(result)

        for msg in result.get("errors", {}):
            if constants.POLICY_NOT_FOUND in msg:
                if resp.status != HTTPStatus.NOT_FOUND:
                    continue

                return

        raise await VaultAPIError.from_response("Failed to read password policy", resp)

    async def generate_password(self, policy_path: str) -> str:
        async with self.new_session() as sess:
            resp = await sess.get("/".join((BASE_PATH, policy_path, "generate")))

        resp_body = await resp.json()
        if resp.status == HTTPStatus.OK:
            return cast(str, resp_body["data"]["password"])
        elif resp.status == HTTPStatus.NOT_FOUND:
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
