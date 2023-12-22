from dataclasses import dataclass

from .. import dto, state
from ..dispatcher import event
from . import abstract


@dataclass(slots=True)
class PasswordPolicyCreateProcessor(abstract.AbstractProcessor):
    state: state.PasswordPolicyState

    def register_handlers(self) -> None:
        async def _on_password_policy_discovered(
            ev: event.PasswordPolicyDiscovered,
        ) -> None:
            """
            Responds to the :class:`event.PasswordPolicyDiscovered` event by
            creating/updating the policy on the Vault server.
            """
            async with self.state.sem:
                await self._process(ev.payload)

        self.state.observer.register(
            (event.PasswordPolicyDiscovered,), _on_password_policy_discovered
        )

    async def _process(self, payload: dto.PasswordPolicyCreateDTO) -> None:
        await self.state.pwd_policy_svc.create_or_update(payload)
        await self.state.observer.trigger(event.PasswordPolicyCreated(payload))
