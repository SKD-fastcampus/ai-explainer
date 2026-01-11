from __future__ import annotations

import json
from typing import Any, Dict, Optional

import firebase_admin
from firebase_admin import auth, credentials
from fastapi import Header, HTTPException, status

from ai_explainer.config import settings


_firebase_app: Optional[firebase_admin.App] = None


def _init_firebase() -> firebase_admin.App:
    global _firebase_app
    if _firebase_app is not None:
        return _firebase_app

    cred = None
    if settings.firebase_credentials_json:
        payload = json.loads(settings.firebase_credentials_json)
        cred = credentials.Certificate(payload)
    elif settings.firebase_credentials_path:
        cred = credentials.Certificate(settings.firebase_credentials_path)
    else:
        cred = credentials.ApplicationDefault()

    _firebase_app = firebase_admin.initialize_app(cred)
    return _firebase_app


def verify_firebase_token(token: str) -> Dict[str, Any]:
    _init_firebase()
    return auth.verify_id_token(token)


async def require_firebase_user(authorization: str | None = Header(default=None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing authorization header")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid authorization scheme")

    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")

    try:
        return verify_firebase_token(token)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid firebase token") from exc
