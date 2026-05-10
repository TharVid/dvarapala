# @dvarapala/sdk

TypeScript SDK for [Dvarapala](https://github.com/tharvid/dvarapala) — drop-in security for Model Context Protocol servers.

```bash
npm install @dvarapala/sdk
```

```ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { wrap } from "@dvarapala/sdk";

const server = wrap(new Server(/* … */), { policyPath: "./policy.yaml" });
```

The SDK delegates detection to the `dvarapala` binary or its sidecars (Presidio, llm-guard). It does not reimplement PII / secrets / prompt-injection detection.
