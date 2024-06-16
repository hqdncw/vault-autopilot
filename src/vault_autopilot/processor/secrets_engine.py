import logging
from dataclasses import dataclass

from typing_extensions import override

from vault_autopilot.service.abstract import ApplyResult

from .. import dto
from ..dispatcher import event
from ..service import SecretsEngineService
from .abstract import AbstractProcessor

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SecretsEngineApplyProcessor(AbstractProcessor[event.EventType]):
    secrets_engine_svc: SecretsEngineService

    @override
    def initialize(self) -> None:
        async def _on_application_requested(
            ev: event.SecretsEngineApplicationRequested,
        ) -> None:
            async with self.sem:
                await self._apply(ev.resource)

        self.observer.register(
            (event.SecretsEngineApplicationRequested,), _on_application_requested
        )

    async def _apply(self, payload: dto.SecretsEngineApplyDTO) -> None:
        await self.observer.trigger(event.SecretsEngineApplicationInitiated(payload))

        ev: event.SecretsEngineApplySuccess | event.SecretsEngineApplyError

        try:
            result = await self.secrets_engine_svc.apply(payload)
        except Exception as exc:
            ev, result = (
                event.SecretsEngineCreateError(payload),
                ApplyResult(status="create_error", errors=(exc,)),
            )
        else:
            match result.get("status"):
                case "verify_success":
                    ev = event.SecretsEngineVerifySuccess(payload)
                case "verify_error":
                    ev = event.SecretsEngineVerifyError(payload)
                case "update_success":
                    ev = event.SecretsEngineUpdateSuccess(payload)
                case "update_error":
                    ev = event.SecretsEngineUpdateError(payload)
                case "create_success":
                    ev = event.SecretsEngineCreateSuccess(payload)
                case "create_error":
                    ev = event.SecretsEngineCreateError(payload)
                case _ as status:
                    raise NotImplementedError(status)
        finally:
            logger.debug("applying finished %r", payload.absolute_path())
            await self.observer.trigger(ev)

        if errors := result.get("errors"):
            raise ExceptionGroup("Failed to apply secrets engine", errors)
