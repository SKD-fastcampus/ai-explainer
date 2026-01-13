from __future__ import annotations

import asyncio
import json
from typing import AsyncGenerator

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from ai_explainer.auth import require_firebase_user
from ai_explainer.db import get_db
from ai_explainer.evidence import build_evidence_bundle, build_evidence_bundle_from_details
from ai_explainer.llm_explain import stream_explanation, stream_message_safety_explanation
from ai_explainer.models import AnalysisResult
from ai_explainer.mock_store import get_mock_log

app = FastAPI(title="AI Explainer", version="0.1.0")


class MessageSafetyRequest(BaseModel):
    message: str
    safe_browsing_result: str = ""


async def _stream_cached_summary(text: str) -> AsyncGenerator[str, None]:
    if not text:
        return
    chunk_size = 20
    for i in range(0, len(text), chunk_size):
        await asyncio.sleep(0.02)
        yield text[i:i + chunk_size]


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/debug/db")
async def debug_db(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_firebase_user),
):
    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail="DB connection failed") from exc
    return {"ok": True}


@app.get("/debug/result/{result_id}")
async def debug_result(
    result_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_firebase_user),
):
    row = await db.get(AnalysisResult, result_id)
    if not row:
        raise HTTPException(status_code=404, detail="result_id not found")
    return {
        "result_id": row.result_id,
        "status": row.status,
        "details": row.details,
    }


class ExplainStreamRequest(BaseModel):
    message: str | None = None


@app.post("/v1/explain/{result_id}/stream")
async def explain_stream(
    result_id: str,
    payload: ExplainStreamRequest,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_firebase_user),
):
    if result_id == "uuid":
        log = get_mock_log(result_id)
        if not log:
            raise HTTPException(status_code=404, detail="mock data not found")
        bundle = build_evidence_bundle(log)
        status_value = log.get("status")
        cached_summary = None
    else:
        row = await db.get(AnalysisResult, result_id)
        if not row or not row.details:
            raise HTTPException(status_code=404, detail="result_id not found")
        bundle = build_evidence_bundle_from_details(result_id, row.details)
        status_value = row.status
        cached_summary = row.llm_summary if not payload.message else None

    async def gen() -> AsyncGenerator[dict, None]:
        yield {"event": "meta", "data": json.dumps({
            "result_id": bundle.request_id,
            "url": bundle.extracted_url,
            "message": payload.message,
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

        if cached_summary:
            async for token in _stream_cached_summary(cached_summary):
                yield {
                    "event": "delta",
                    "data": json.dumps({"text": token}, ensure_ascii=False),
                }
        else:
            collected: list[str] = []
            async for token in stream_explanation(bundle, message=payload.message):
                collected.append(token)
                yield {
                    "event": "delta",
                    "data": json.dumps({"text": token}, ensure_ascii=False),
                }
            if result_id != "uuid" and not payload.message:
                full_text = "".join(collected)
                row.llm_summary = full_text
                if not row.message_text:
                    row.message_text = payload.message or None
                try:
                    await db.commit()
                except Exception:
                    await db.rollback()

        yield {
            "event": "done",
            "data": json.dumps({"status": "OK"}, ensure_ascii=False),
        }

    return EventSourceResponse(gen())


@app.post("/v1/message/explain/stream")
async def explain_message_stream(
    payload: MessageSafetyRequest,
    _: dict = Depends(require_firebase_user),
):
    async def gen() -> AsyncGenerator[dict, None]:
        yield {"event": "meta", "data": json.dumps({
            "message": payload.message,
            "safe_browsing_result": payload.safe_browsing_result,
        }, ensure_ascii=False)}

        async for token in stream_message_safety_explanation(
            payload.message,
            payload.safe_browsing_result,
        ):
            yield {
                "event": "delta",
                "data": json.dumps({"text": token}, ensure_ascii=False),
            }

        yield {
            "event": "done",
            "data": json.dumps({"status": "OK"}, ensure_ascii=False),
        }

    return EventSourceResponse(gen())
