from __future__ import annotations

import json
from typing import AsyncGenerator

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from ai_explainer.auth import require_firebase_user
from ai_explainer.db import get_db
from ai_explainer.evidence import build_evidence_bundle, build_evidence_bundle_from_details
from ai_explainer.llm_explain import (
    stream_explanation,
    stream_message_safety_explanation,
    stream_message_safety_explanation_multi,
)
from ai_explainer.models import AnalysisResult
from ai_explainer.mock_store import get_mock_log

app = FastAPI(title="AI Explainer", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://detective-crab.vercel.app"],
    allow_credentials=True,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


class MessageSafetyRequest(BaseModel):
    message: str
    safe_browsing_result: str = ""


class MessageSafetyMultiItem(BaseModel):
    link: str
    safe_browsing_result: str = ""


class MessageSafetyMultiRequest(BaseModel):
    message: str
    items: list[MessageSafetyMultiItem]


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
    result_ids: list[str]
    message: str | None = None


class ExplainSingleStreamRequest(BaseModel):
    message: str | None = None


@app.post("/v1/explain/{result_id}/stream")
async def explain_single_stream(
    result_id: str,
    payload: ExplainSingleStreamRequest,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_firebase_user),
):
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

    if payload.message:
        bundle = bundle.model_copy(update={"raw_text": payload.message})

    async def gen() -> AsyncGenerator[dict, None]:
        yield {"event": "meta", "data": json.dumps({
            "result_id": bundle.request_id,
            "url": bundle.extracted_url,
            "message": bundle.raw_text,
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

        async for token in stream_explanation([bundle]):
            yield {
                "event": "delta",
                "data": json.dumps({"text": token}, ensure_ascii=False),
            }

        yield {
            "event": "done",
            "data": json.dumps({"status": "OK"}, ensure_ascii=False),
        }

    return EventSourceResponse(gen())


@app.post("/v1/explain/stream")
async def explain_stream(
    payload: ExplainStreamRequest,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_firebase_user),
):
    if not payload.result_ids:
        raise HTTPException(status_code=400, detail="result_ids is required")

    bundles: list = []
    status_values: list[str | None] = []

    for result_id in payload.result_ids:
        if result_id == "uuid":
            log = get_mock_log(result_id)
            if not log:
                continue
            bundles.append(build_evidence_bundle(log))
            status_values.append(log.get("status"))
            continue

        row = await db.get(AnalysisResult, result_id)
        if not row or not row.details:
            continue
        bundles.append(build_evidence_bundle_from_details(result_id, row.details))
        status_values.append(row.status)

    if not bundles:
        raise HTTPException(status_code=404, detail="result_id not found")

    if payload.message:
        bundles = [bundle.model_copy(update={"raw_text": payload.message}) for bundle in bundles]

    async def gen() -> AsyncGenerator[dict, None]:
        meta_items = []
        evidence_items = []
        for bundle, status_value in zip(bundles, status_values):
            meta_items.append({
                "result_id": bundle.request_id,
                "url": bundle.extracted_url,
                "message": bundle.raw_text,
                "risk_level": bundle.risk_level,
                "risk_score": bundle.risk_score,
                "screenshot": bundle.screenshot,
                "status": status_value,
            })
            evidence_items.append({
                "result_id": bundle.request_id,
                "coverage": bundle.coverage,
                "limitations": bundle.limitations,
                "evidence": [e.model_dump() for e in bundle.evidence],
            })

        yield {"event": "meta", "data": json.dumps({"items": meta_items}, ensure_ascii=False)}
        yield {"event": "evidence", "data": json.dumps({"items": evidence_items}, ensure_ascii=False)}

        async for token in stream_explanation(bundles):
            yield {
                "event": "delta",
                "data": json.dumps({"text": token}, ensure_ascii=False),
            }

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


@app.post("/v1/message/explain/multi/stream")
async def explain_message_multi_stream(
    payload: MessageSafetyMultiRequest,
    _: dict = Depends(require_firebase_user),
):
    if not payload.items:
        raise HTTPException(status_code=400, detail="items is required")

    async def gen() -> AsyncGenerator[dict, None]:
        yield {"event": "meta", "data": json.dumps({
            "message": payload.message,
            "items": [item.model_dump() for item in payload.items],
        }, ensure_ascii=False)}

        async for token in stream_message_safety_explanation_multi(
            payload.message,
            [item.model_dump() for item in payload.items],
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
