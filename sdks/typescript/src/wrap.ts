import { Gateway, type GatewayOptions } from "./gateway.js";

export interface WrapOptions extends GatewayOptions {}

/**
 * Wrap an `@modelcontextprotocol/sdk` Server so every `setRequestHandler`
 * for `CallToolRequestSchema` is policy-checked before invocation.
 *
 * Implementation lands once Server hooks are confirmed in upstream MCP SDK.
 */
export function wrap<S>(server: S, opts: WrapOptions = {}): S {
  const gateway = new Gateway(opts);
  // TODO: intercept server.setRequestHandler(CallToolRequestSchema, ...)
  void gateway;
  return server;
}
