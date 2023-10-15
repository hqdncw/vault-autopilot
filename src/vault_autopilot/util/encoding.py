import base64


def base64_encode(value: str) -> str:
    return base64.b64encode(value.encode()).decode()
