from hcl2.api import loads as hcl2_loads

from ..dto.password_policy import CharsetRule, PasswordPolicy


def deseralize_password_policy(value: str) -> PasswordPolicy:
    payload = hcl2_loads(value)
    return PasswordPolicy(
        length=payload["length"],
        rules=tuple(
            CharsetRule(
                charset=rule["charset"]["charset"],
                min_chars=rule["charset"]["min-chars"],
            )
            for rule in payload["rule"]
        ),
    )
