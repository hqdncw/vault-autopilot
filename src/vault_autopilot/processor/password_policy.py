import logging
from dataclasses import dataclass

from .. import dto, state
from ..dispatcher import event
from . import abstract

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PasswordPolicyApplyProcessor(abstract.AbstractProcessor):
    state: state.PasswordPolicyState

    def register_handlers(self) -> None:
        async def _on_password_policy_apply_requested(
            ev: event.PasswordPolicyApplyRequested,
        ) -> None:
            """
            Responds to the :class:`event.PasswordPolicyApplyRequested` event by
            creating/updating the policy on the Vault server.
            """
            async with self.state.sem:
                await self._process(ev.resource)

        self.state.observer.register(
            (event.PasswordPolicyApplyRequested,), _on_password_policy_apply_requested
        )

    async def _process(self, payload: dto.PasswordPolicyApplyDTO) -> None:
        await self.state.observer.trigger(event.PasswordPolicyApplyStarted(payload))

        # TODO: VerifySuccess, VerifyError, UpdateSuccess, UpdateError
        try:
            await self.state.pwd_policy_svc.update_or_create(payload)
        except Exception:
            await self.state.observer.trigger(event.PasswordPolicyCreateError(payload))
            raise

        await self.state.observer.trigger(event.PasswordPolicyCreateSuccess(payload))

        logger.debug(
            "password policy resource applying finished: %r", payload.absolute_path()
        )
