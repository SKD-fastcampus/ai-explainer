from __future__ import annotations

import json
from typing import AsyncGenerator

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from ai_explainer.db import get_db
from ai_explainer.evidence import build_evidence_bundle, build_evidence_bundle_from_details
from ai_explainer.llm_explain import stream_explanation
from ai_explainer.models import AnalysisResult
from ai_explainer.mock_store import get_mock_log

app = FastAPI(title="AI Explainer", version="0.1.0")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/debug/db")
async def debug_db(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail="DB connection failed") from exc
    return {"ok": True}


@app.get("/debug/result/{result_id}")
async def debug_result(result_id: str, db: AsyncSession = Depends(get_db)):
    row = await db.get(AnalysisResult, result_id)
    if not row:
        raise HTTPException(status_code=404, detail="result_id not found")
    return {
        "result_id": row.result_id,
        "status": row.status,
        "details": row.details,
    }


@app.get("/v1/explain/{result_id}/stream")
async def explain_stream(result_id: str, db: AsyncSession = Depends(get_db)):
    if result_id == "uuid":
        log = get_mock_log(result_id)
        if not log:
            raise HTTPException(status_code=404, detail="mock data not found")
        bundle = build_evidence_bundle(log)
        status_value = log.get("status")
    else:
        row = await db.get(AnalysisResult, result_id)
        if not row or not row.details:
            raise HTTPException(status_code=404, detail="result_id not found")
        bundle = build_evidence_bundle_from_details(result_id, row.details)
        status_value = row.status

    async def gen() -> AsyncGenerator[dict, None]:
        yield {"event": "meta", "data": json.dumps({
            "result_id": bundle.request_id,
            "url": bundle.extracted_url,
            "risk_level": bundle.risk_level,
            "risk_score": bundle.risk_score,
            "screenshot": bundle.screenshot,
            "status": status_value,
        }, ensure_ascii=False)}

        yield {"event": "evidence", "data": json.dumps({
            "coverage": bundle.coverage,
            "limitations": bundle.limitations,
            "evidence": [e.model_dump() for e in bundle.evidence],
        }, ensure_ascii=False)}

        async for token in stream_explanation(bundle):
            yield {
                "event": "delta",
                "data": json.dumps({"text": token}, ensure_ascii=False),
            }

        yield {
            "event": "done",
            "data": json.dumps({"status": "OK"}, ensure_ascii=False),
        }

    return EventSourceResponse(gen())
