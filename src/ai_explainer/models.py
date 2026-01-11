from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.dialects.mysql import JSON
from sqlalchemy.orm import Mapped, mapped_column

from ai_explainer.db import Base


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    result_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
