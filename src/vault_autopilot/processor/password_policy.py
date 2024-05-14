import logging
from dataclasses import dataclass
from typing_extensions import override

from ..service import PasswordPolicyService

from .. import dto
from ..dispatcher import event
from . import abstract

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PasswordPolicyApplyProcessor(abstract.AbstractProcessor):
    pwd_policy_svc: PasswordPolicyService

    @override
    def initialize(self) -> None:
        async def _on_password_policy_apply_requested(
            ev: event.PasswordPolicyApplyRequested,
        ) -> None:
            """
            Responds to the :class:`event.PasswordPolicyApplyRequested` event by
            creating/updating the policy on the Vault server.
            """
            async with self.sem:
                await self._apply(ev.resource)

        self.observer.register(
            (event.PasswordPolicyApplyRequested,), _on_password_policy_apply_requested
        )

    async def _apply(self, payload: dto.PasswordPolicyApplyDTO) -> None:
        await self.observer.trigger(event.PasswordPolicyApplyStarted(payload))

        # TODO: VerifySuccess, VerifyError, UpdateSuccess, UpdateError
        try:
            await self.pwd_policy_svc.update_or_create(payload)
        except Exception:
            await self.observer.trigger(event.PasswordPolicyCreateError(payload))
            raise

        await self.observer.trigger(event.PasswordPolicyCreateSuccess(payload))

        logger.debug(
            "applying finished %r", payload.absolute_path()
        )
