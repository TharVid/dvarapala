export interface GatewayOptions {
  /** Absolute path to a Dvarapala policy YAML. */
  policyPath?: string;
  /** Optional hub URL for HTTP-mode checks. */
  hubUrl?: string;
}

export class Gateway {
  readonly policyPath: string;
  readonly hubUrl?: string;

  constructor(opts: GatewayOptions = {}) {
    this.policyPath =
      opts.policyPath ?? process.env.DVARAPALA_POLICY ?? "policy.yaml";
    this.hubUrl = opts.hubUrl ?? process.env.DVARAPALA_HUB_URL;
  }

  /**
   * Check a tool call against policy. Stub implementation — wires to the
   * dvarapala binary or hub once the core implements the check API.
   */
  async check(_tool: string, _args: Record<string, unknown>): Promise<void> {
    return;
  }
}
