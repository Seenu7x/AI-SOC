"""
Pydantic schemas for compliance mapping feature
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class FrameworkCode(str, Enum):
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    GDPR = "gdpr"


class EvidenceStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    PENDING = "pending"


# ─── Framework ─────────────────────────────────────────────────────────────────

class FrameworkResponse(BaseModel):
    id: int
    name: str
    code: str
    version: Optional[str]
    description: Optional[str]
    category: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ─── Control ───────────────────────────────────────────────────────────────────

class ControlResponse(BaseModel):
    id: int
    framework_id: int
    control_id: str
    title: str
    description: Optional[str]
    category: Optional[str]
    subcategory: Optional[str]
    related_event_types: Optional[List[str]]
    triggers_on_anomaly: bool
    severity_threshold: Optional[str]

    class Config:
        from_attributes = True


# ─── Evidence ──────────────────────────────────────────────────────────────────

class EvidenceResponse(BaseModel):
    id: int
    control_id: int
    framework_id: int
    evidence_type: Optional[str]
    event_id: Optional[int]
    alert_id: Optional[int]
    title: Optional[str]
    description: Optional[str]
    status: str
    collected_at: datetime

    class Config:
        from_attributes = True


# ─── Compliance Status ─────────────────────────────────────────────────────────

class FrameworkStatus(BaseModel):
    framework_code: str
    framework_name: str
    total_controls: int
    controls_with_evidence: int
    compliance_percentage: float
    last_updated: Optional[str]


class ComplianceStatusResponse(BaseModel):
    frameworks: List[FrameworkStatus]
    overall_compliance: float
    total_evidence_items: int
    assessment_time: str


# ─── Mapping Result ────────────────────────────────────────────────────────────

class MappingResultItem(BaseModel):
    control_id: str
    control_title: str
    framework: str
    reason: str
    confidence: float


class MappingResponse(BaseModel):
    event_id: int
    alert_id: Optional[int]
    controls_mapped: int
    mappings: List[MappingResultItem]
    evidence_collected: int
    message: str


# ─── Report ────────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    framework: FrameworkCode = Field(..., description="Compliance framework to report on")
    time_period_hours: int = Field(default=24, ge=1, le=8760, description="Look-back window in hours")

    model_config = {"json_schema_extra": {
        "example": {"framework": "nist_csf", "time_period_hours": 24}
    }}


class ReportResponse(BaseModel):
    id: int
    title: str
    framework_code: str
    total_controls: int
    controls_with_evidence: int
    compliance_percentage: float
    total_events_analyzed: int
    total_anomalies: int
    total_alerts: int
    report_data: Optional[Dict[str, Any]]
    time_period_hours: int
    generated_at: datetime

    class Config:
        from_attributes = True
