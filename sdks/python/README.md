# dvarapala — Python SDK

Embed Dvarapala policy enforcement into a Python MCP server.

```bash
pip install dvarapala
```

```python
from dvarapala import Gateway
from mcp.server.fastmcp import FastMCP

gw = Gateway.from_yaml("policy.yaml")
mcp = FastMCP("my-tools")

@mcp.tool()
@gw.protect
async def query_db(sql: str) -> str:
    ...

mcp.run()
```

The SDK delegates detection to the `dvarapala` binary or running sidecars
(Presidio, llm-guard) — it does not reinvent PII / secrets / prompt-injection
detection in pure Python.
