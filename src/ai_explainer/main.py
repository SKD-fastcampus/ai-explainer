from __future__ import annotations

import json
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from sse_starlette.sse import EventSourceResponse

from ai_explainer.mock_store import get_mock_log
from ai_explainer.evidence import build_evidence_bundle
from ai_explainer.llm_explain import stream_explanation

app = FastAPI(title="AI Explainer", version="0.1.0")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/v1/explain/{request_id}/stream")
async def explain_stream(request_id: str):
    log = get_mock_log(request_id)
    if not log:
        raise HTTPException(status_code=404, detail="request_id not found in MOCK_LOGS")

    bundle = build_evidence_bundle(log)

    async def gen() -> AsyncGenerator[dict, None]:
        yield {"event": "meta", "data": json.dumps({
            "request_id": bundle.request_id,
            "url": bundle.extracted_url,
            "risk_level": bundle.risk_level,
            "risk_score": bundle.risk_score,
            "screenshot": bundle.screenshot,
            "text":"",
        }, ensure_ascii=False)}

        yield {"event": "evidence", "data": json.dumps({
            "coverage": bundle.coverage,
            "limitations": bundle.limitations,
            "evidence": [e.model_dump() for e in bundle.evidence],
            "text":"",
        }, ensure_ascii=False)}

        async for token in stream_explanation(bundle):
            yield {
                "event": "delta",
                "data": json.dumps({
                    "text": token
                }, ensure_ascii=False)
            }

        yield {
            "event": "done",
            "data": json.dumps({"status": "OK","text":""})
        }

    return EventSourceResponse(gen())
