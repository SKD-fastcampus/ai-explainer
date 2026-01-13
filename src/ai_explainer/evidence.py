from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    key: str
    severity: str  # HIGH/MEDIUM/LOW
    message: str
    why_it_matters: str
    user_action: str


class EvidenceBundle(BaseModel):
    request_id: str
    extracted_url: str
    target_url: str = ""
    final_url: str = ""
    raw_text: str = ""
    risk_level: str
    risk_score: float
    screenshot: Optional[Dict[str, str]] = None
    redirect_chain: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    coverage: str = "UNKNOWN"  # ALL | PARTIAL
    limitations: List[str] = Field(default_factory=list)


def _build_evidence_from_details(details: Dict[str, Any]) -> List[EvidenceItem]:
    evidence: List[EvidenceItem] = []

    download = details.get("download_attempt") or {}
    technical = details.get("technical_findings") or {}
    behavioral = details.get("behavioral_findings") or {}
    domain = details.get("domain_analysis") or {}
    cert = details.get("certificate_analysis") or {}

    filename = str(download.get("filename") or "")
    is_apk = filename.lower().endswith(".apk")
    if download.get("attempted") and is_apk:
        evidence.append(EvidenceItem(
            key="download_apk",
            severity="HIGH",
            message=f"APK 파일 다운로드 시도가 감지되었습니다: {filename or 'unknown'}",
            why_it_matters="APK 설치는 악성 앱 설치로 이어질 수 있어 계정 탈취 위험이 큽니다.",
            user_action="앱 설치나 다운로드는 즉시 중단하세요."
        ))

    if technical.get("credential_exfiltration") or behavioral.get("external_post_on_input"):
        evidence.append(EvidenceItem(
            key="credential_exfiltration",
            severity="HIGH",
            message="입력 정보를 외부로 전송하려는 동작이 감지되었습니다.",
            why_it_matters="아이디, 비밀번호, 인증번호가 공격자에게 전달될 수 있습니다.",
            user_action="링크에서 로그인이나 개인정보 입력을 하지 마세요."
        ))

    if behavioral.get("keystroke_capture"):
        evidence.append(EvidenceItem(
            key="keystroke_capture",
            severity="HIGH",
            message="키 입력을 수집하려는 스크립트가 감지되었습니다.",
            why_it_matters="입력 내용이 몰래 기록되어 탈취될 수 있습니다.",
            user_action="입력창에 아무것도 입력하지 마세요."
        ))

    if technical.get("ui_deception"):
        evidence.append(EvidenceItem(
            key="ui_deception",
            severity="MEDIUM",
            message="가짜 UI로 사용자를 속이려는 정황이 보입니다.",
            why_it_matters="공식 화면처럼 보이게 만들어 개인정보 입력을 유도할 수 있습니다.",
            user_action="화면이 그럴듯해 보여도 믿지 말고 접속을 중단하세요."
        ))

    if technical.get("brand_impersonation"):
        evidence.append(EvidenceItem(
            key="brand_impersonation",
            severity="MEDIUM",
            message="브랜드나 도메인 위장을 시도한 정황이 있습니다.",
            why_it_matters="공식 사이트처럼 보이게 만들어 사용자를 속일 수 있습니다.",
            user_action="도메인을 꼼꼼히 확인하고 의심되면 접속을 중단하세요."
        ))

    age_days = domain.get("domain_age_days")
    if isinstance(age_days, (int, float)) and age_days <= 7:
        evidence.append(EvidenceItem(
            key="new_domain",
            severity="MEDIUM",
            message=f"도메인이 생성된 지 {int(age_days)}일로 매우 최근입니다.",
            why_it_matters="피싱 사이트는 짧게 만들고 빠르게 폐기하는 경우가 많습니다.",
            user_action="로그인이나 인증 요구가 있으면 즉시 중단하세요."
        ))

    if cert.get("suspicious"):
        issuer = cert.get("issuer") or "unknown"
        evidence.append(EvidenceItem(
            key="cert_recent",
            severity="LOW",
            message=f"TLS 인증서가 최근 발급된 것으로 보입니다. (issuer={issuer})",
            why_it_matters="피싱 사이트에서도 흔히 보이는 특징이라 참고가 필요합니다.",
            user_action="인증서만 믿지 말고 다른 위험 신호도 함께 보세요."
        ))

    return evidence


def build_evidence_bundle(log: Dict[str, Any]) -> EvidenceBundle:
    request_id = str(log.get("request_id") or "unknown")

    original_input = log.get("original_input") or {}
    extracted_url = str(original_input.get("extracted_url") or "")
    raw_text = str(original_input.get("raw_text") or "")

    summary = log.get("summary") or {}
    risk_level = str(summary.get("risk_level") or "UNKNOWN")
    risk_score = _parse_risk_score(summary.get("risk_score"))

    screenshot = log.get("visual_snapshot_storage")

    result = log.get("result") or {}
    redirect_chain = result.get("redirect_chain") or []

    confidence = log.get("confidence") or {}
    coverage = str(confidence.get("analysis_coverage") or "UNKNOWN")
    limitations = confidence.get("limitations") or []

    evidence = _build_evidence_from_details(result)

    return EvidenceBundle(
        request_id=request_id,
        extracted_url=extracted_url,
        target_url=extracted_url,
        raw_text=raw_text,
        risk_level=risk_level,
        risk_score=risk_score,
        screenshot=screenshot,
        redirect_chain=redirect_chain,
        evidence=evidence,
        coverage=coverage,
        limitations=limitations,
    )


def build_evidence_bundle_from_details(result_id: str, payload: Dict[str, Any]) -> EvidenceBundle:
    summary = payload.get("summary") or {}
    risk_level = str(summary.get("risk_level") or "UNKNOWN")
    risk_score = _parse_risk_score(summary.get("risk_score"))

    target_url = str(payload.get("target_url") or "")
    final_url = str(payload.get("final_url") or "")
    extracted_url = target_url or final_url
    screenshot = payload.get("screenshot") or payload.get("visual_snapshot_storage")

    details = payload.get("details") or {}
    redirect_chain = details.get("redirect_chain") or []
    evidence = _build_evidence_from_details(details)

    confidence = payload.get("confidence") or {}
    coverage = str(confidence.get("analysis_coverage") or "UNKNOWN")
    limitations = confidence.get("limitations") or []

    return EvidenceBundle(
        request_id=result_id,
        extracted_url=extracted_url,
        target_url=target_url,
        final_url=final_url,
        raw_text="",
        risk_level=risk_level,
        risk_score=risk_score,
        screenshot=screenshot,
        redirect_chain=redirect_chain,
        evidence=evidence,
        coverage=coverage,
        limitations=limitations,
    )


def _parse_risk_score(value: Any) -> float:
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
