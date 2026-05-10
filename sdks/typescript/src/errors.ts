export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

export class PolicyDenied extends PolicyError {
  rule: string;
  reason: string;

  constructor(rule: string, reason: string) {
    super(`denied by rule '${rule}': ${reason}`);
    this.name = "PolicyDenied";
    this.rule = rule;
    this.reason = reason;
  }
}
