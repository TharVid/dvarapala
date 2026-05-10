/**
 * @dvarapala/sdk — TypeScript SDK for Dvarapala MCP security gateway.
 *
 * Two integration patterns:
 *   1. wrap(server, options) — wrap an existing @modelcontextprotocol/sdk Server
 *      so every tool call is policy-checked.
 *   2. createGateway(options) — manual check API for custom integrations.
 *
 * The SDK delegates detection to the dvarapala core binary or its sidecars
 * (Presidio, llm-guard). We do not reinvent PII / secrets / prompt-injection
 * detection in TypeScript.
 */

export { Gateway, type GatewayOptions } from "./gateway.js";
export { wrap, type WrapOptions } from "./wrap.js";
export { PolicyDenied, PolicyError } from "./errors.js";
