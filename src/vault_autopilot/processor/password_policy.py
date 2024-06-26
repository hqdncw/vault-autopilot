import logging
from dataclasses import dataclass

from typing_extensions import override

from vault_autopilot.service.abstract import ApplyResult

from .. import dto
from ..dispatcher import event
from ..service import PasswordPolicyService
from .abstract import AbstractProcessor

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PasswordPolicyApplyProcessor(AbstractProcessor[event.EventType]):
    pwd_policy_svc: PasswordPolicyService

    @override
    def initialize(self) -> None:
        async def _on_password_policy_apply_requested(
            ev: event.PasswordPolicyApplicationRequested,
        ) -> None:
            """
            Responds to the :class:`event.PasswordPolicyApplicationRequested` event by
            creating/updating the policy on the Vault server.
            """
            async with self.sem:
                await self.apply(ev.resource)

        self.observer.register(
            (event.PasswordPolicyApplicationRequested,),
            _on_password_policy_apply_requested,
        )

    async def apply(self, payload: dto.PasswordPolicyApplyDTO) -> None:
        await self.observer.trigger(event.PasswordPolicyApplicationInitiated(payload))

        try:
            result = await self.pwd_policy_svc.apply(payload)
        except Exception as exc:
            ev, result = (
                event.PasswordPolicyVerifyError(payload),
                ApplyResult(status="verify_error", error=exc),
            )
        else:
            match result.get("status"):
                case "verify_success":
                    ev = event.PasswordPolicyVerifySuccess(payload)
                case "verify_error":
                    ev = event.PasswordPolicyVerifyError(payload)
                case "update_success":
                    ev = event.PasswordPolicyUpdateSuccess(payload)
                case "update_error":
                    ev = event.PasswordPolicyUpdateError(payload)
                case "create_success":
                    ev = event.PasswordPolicyCreateSuccess(payload)
                case "create_error":
                    ev = event.PasswordPolicyCreateError(payload)
                case _ as status:
                    raise NotImplementedError(status)
        finally:
            if "ev" in locals().keys():
                logger.debug("applying finished %r", payload.absolute_path())

                await self.observer.trigger(ev)

        if error := result.get("error"):
            raise error
