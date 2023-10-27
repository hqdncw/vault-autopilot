from dataclasses import dataclass

from .. import dto, state


@dataclass(slots=True)
class PassowrdPolicyCreateProcessor:
    state: state.PasswordPolicyState

    async def process(self, payload: dto.PasswordPolicyCreateDTO) -> None:
        await self.state.pwd_policy_svc.create_or_update(payload)
