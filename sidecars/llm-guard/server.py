"""Thin FastAPI wrapper around llm-guard so Dvarapala can call it over HTTP.

We do not reinvent prompt-injection detection. We host the OSS llm-guard
scanners and expose a /scan endpoint.
"""

from fastapi import FastAPI
from pydantic import BaseModel
from llm_guard.input_scanners import PromptInjection
from llm_guard.output_scanners import Sensitive

app = FastAPI(title="dvarapala-llm-guard-sidecar")

prompt_scanner = PromptInjection()
output_scanner = Sensitive()


class ScanRequest(BaseModel):
    text: str
    direction: str = "inbound"  # inbound | outbound


class ScanResponse(BaseModel):
    is_valid: bool
    risk_score: float
    detector: str


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    if req.direction == "inbound":
        sanitized, is_valid, risk = prompt_scanner.scan(req.text)
        return ScanResponse(is_valid=is_valid, risk_score=risk, detector="prompt-injection")
    sanitized, is_valid, risk = output_scanner.scan(req.text, req.text)
    return ScanResponse(is_valid=is_valid, risk_score=risk, detector="sensitive-output")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
