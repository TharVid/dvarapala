import asyncio
from dvarapala import Gateway


def test_import() -> None:
    assert Gateway is not None


def test_decorator_passthrough(tmp_path) -> None:
    p = tmp_path / "policy.yaml"
    p.write_text("version: '1'\nrules: []\n")
    gw = Gateway.from_yaml(p)

    @gw.protect
    async def my_tool(x: int) -> int:
        return x * 2

    assert asyncio.run(my_tool(3)) == 6
