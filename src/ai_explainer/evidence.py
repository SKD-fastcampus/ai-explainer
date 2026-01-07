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
    raw_text: str = ""
    risk_level: str
    risk_score: int
    screenshot: Optional[Dict[str, str]] = None
    redirect_chain: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    coverage: str = "UNKNOWN"  # ALL | PARTIAL
    limitations: List[str] = Field(default_factory=list)


def build_evidence_bundle(log: Dict[str, Any]) -> EvidenceBundle:
    request_id = str(log.get("request_id") or "unknown")

    original_input = log.get("original_input") or {}
    extracted_url = str(original_input.get("extracted_url") or "")
    raw_text = str(original_input.get("raw_text") or "")

    summary = log.get("summary") or {}
    risk_level = str(summary.get("risk_level") or "UNKNOWN")
    risk_score = int(summary.get("risk_score") or 0)

    screenshot = log.get("visual_snapshot_storage")

    result = log.get("result") or {}
    redirect_chain = result.get("redirect_chain") or []

    download = result.get("download_attempt") or {}
    technical = result.get("technical_findings") or {}
    behavioral = result.get("behavioral_findings") or {}
    domain = result.get("domain_analysis") or {}
    cert = result.get("certificate_analysis") or {}

    confidence = log.get("confidence") or {}
    coverage = str(confidence.get("analysis_coverage") or "UNKNOWN")
    limitations = confidence.get("limitations") or []

    evidence: List[EvidenceItem] = []

    if download.get("attempted") and str(download.get("mime_type") or "").startswith("application/vnd.android.package-archive"):
        evidence.append(EvidenceItem(
            key="download_apk",
            severity="HIGH",
            message=f"APK 파일 다운로드를 유도/시도했어요: {download.get('filename', 'unknown')}",
            why_it_matters="APK는 앱 설치 파일이라 설치되면 원격제어/계정탈취 등 큰 피해로 이어질 수 있어요.",
            user_action="절대 설치하지 말고, 이미 다운로드했다면 즉시 삭제하세요."
        ))

    if technical.get("credential_exfiltration") or behavioral.get("external_post_on_input"):
        evidence.append(EvidenceItem(
            key="credential_exfiltration",
            severity="HIGH",
            message="입력/로그인 정보를 외부로 전송하려는 정황이 있어요.",
            why_it_matters="아이디/비밀번호/인증번호가 공격자 서버로 넘어갈 수 있어요.",
            user_action="이 링크에서 로그인/개인정보 입력은 절대 하지 마세요."
        ))

    if behavioral.get("keystroke_capture"):
        evidence.append(EvidenceItem(
            key="keystroke_capture",
            severity="HIGH",
            message="키 입력을 수집하려는 스크립트 정황이 있어요.",
            why_it_matters="입력 내용을 몰래 기록해 탈취할 수 있어요.",
            user_action="입력창에 어떤 것도 타이핑하지 마세요."
        ))

    if technical.get("ui_deception"):
        evidence.append(EvidenceItem(
            key="ui_deception",
            severity="MEDIUM",
            message="화면을 속이거나(가짜 UI/숨김 입력 등) 사용자를 착각하게 만드는 흔적이 있어요.",
            why_it_matters="공식 화면처럼 보이게 만들어 개인정보 입력을 유도하는 피싱에서 자주 보이는 패턴이에요.",
            user_action="화면이 그럴듯해도 믿지 말고, 공식 앱/공식 즐겨찾기에서만 접속하세요."
        ))

    if technical.get("brand_impersonation"):
        evidence.append(EvidenceItem(
            key="brand_impersonation",
            severity="MEDIUM",
            message="브랜드/도메인 사칭(철자 유사/동형문자 등) 가능성이 있어요.",
            why_it_matters="공식 도메인과 비슷하게 꾸며 사용자를 속이는 대표적인 수법이에요.",
            user_action="도메인을 한 글자씩 확인하고, 의심되면 접속을 중단하세요."
        ))

    age_days = domain.get("domain_age_days")
    if isinstance(age_days, (int, float)) and age_days <= 7:
        evidence.append(EvidenceItem(
            key="new_domain",
            severity="MEDIUM",
            message=f"도메인이 생성된 지 {int(age_days)}일로 매우 최근이에요.",
            why_it_matters="피싱 사이트는 짧게 만들고 빠르게 버리는 경우가 많아 신규 도메인이 자주 등장해요.",
            user_action="특히 ‘로그인/인증’ 요구가 있으면 즉시 중단하세요."
        ))

    if cert.get("suspicious"):
        evidence.append(EvidenceItem(
            key="cert_recent",
            severity="LOW",
            message=f"TLS 인증서가 최근 발급된 흔적이 있어요(issuer={cert.get('issuer')}).",
            why_it_matters="정상 사이트도 그럴 수 있지만, 피싱에서도 자주 보이는 ‘참고 신호’예요.",
            user_action="이 신호 하나만 믿지 말고, 다른 위험 징후와 함께 판단하세요."
        ))

    return EvidenceBundle(
        request_id=request_id,
        extracted_url=extracted_url,
        raw_text=raw_text,
        risk_level=risk_level,
        risk_score=risk_score,
        screenshot=screenshot,
        redirect_chain=redirect_chain,
        evidence=evidence,
        coverage=coverage,
        limitations=limitations,
    )
