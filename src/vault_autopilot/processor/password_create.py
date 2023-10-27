from dataclasses import dataclass

from .. import dto, state


@dataclass(slots=True)
class PasswordCreateProcessor:
    state: state.PasswordState

    async def process(self, payload: dto.PasswordCreateDTO) -> None:
        await self.state.pwd_svc.create(payload)
