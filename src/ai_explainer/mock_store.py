from __future__ import annotations

from typing import Any, Dict


MOCK_LOGS: Dict[str, Dict[str, Any]] = {
    "uuid": {
        "request_id": "uuid",
        "user_id": "userid",
        "submitted_at": "2026-01-06T09:32:11Z",
        "original_input": {
            "raw_text": "...",
            "extracted_url": "https://www.naver.com",
        },
        "summary": {
            "risk_level": "HIGH",
            "risk_score": 87,
        },
        "visual_snapshot_storage": {
            "provider": "s3",
            "bucket": "screenshots",
            "key": "snapshots/2026/01/abc123.png",
            "region": "ap-northeast-2",
        },
        "result": {
            "redirect_chain": [
                {"type": "HTTP", "from": "http://bit.ly/xxx", "to": "https://example.com", "status": 302},
                {"type": "JS", "from": "https://example.com", "to": "https://secure-login-example.net"},
            ],
            "download_attempt": {
                "attempted": True,
                "mime_type": "application/vnd.android.package-archive",
                "filename": "SecurityUpdate.apk",
                "content_disposition": "attachment",
                "auto_triggered": True,
            },
            "technical_findings": {
                "ui_deception": True,
                "credential_exfiltration": True,
                "brand_impersonation": True,
            },
            "behavioral_findings": {
                "keystroke_capture": True,
                "external_post_on_input": True,
                "eval_usage_count": 12,
                "tab_control_script": True,
            },
            "domain_analysis": {"domain_age_days": 3},
            "certificate_analysis": {
                "issuer": "Let's Encrypt",
                "issued_days_ago": 2,
                "domain_mismatch": False,
                "suspicious": True,
            },
        },
        "confidence": {"analysis_coverage": "PARTIAL", "limitations": ["CAPTCHA", "OBFUSCATION"]},
    }
}


def get_mock_log(request_id: str) -> Dict[str, Any] | None:
    return MOCK_LOGS.get(request_id)
