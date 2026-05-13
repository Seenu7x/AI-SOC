"""
Compliance Mapping API endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.db.session import get_db
from app.models.compliance import (
    ComplianceFramework, ComplianceControl, ComplianceEvidence, ComplianceReport
)
from app.schemas.compliance_schemas import (
    FrameworkResponse, ControlResponse, EvidenceResponse,
    MappingResponse, ComplianceStatusResponse,
    ReportRequest, ReportResponse
)
from app.services.compliance_service import compliance_service
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


# ─── Frameworks ────────────────────────────────────────────────────────────────

@router.get("/frameworks", response_model=List[FrameworkResponse])
async def list_frameworks(db: Session = Depends(get_db)):
    """List all supported compliance frameworks"""
    return db.query(ComplianceFramework).filter_by(is_active=True).all()


# ─── Controls ──────────────────────────────────────────────────────────────────

@router.get("/controls", response_model=List[ControlResponse])
async def list_controls(
    framework: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List compliance controls, optionally filtered by framework code"""
    query = db.query(ComplianceControl).filter_by(is_active=True)

    if framework:
        fw = db.query(ComplianceFramework).filter_by(code=framework).first()
        if not fw:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Framework '{framework}' not found. Use: nist_csf, iso_27001, soc2, gdpr"
            )
        query = query.filter_by(framework_id=fw.id)

    return query.all()


# ─── Event Mapping ─────────────────────────────────────────────────────────────

@router.post("/map-event/{event_id}", response_model=MappingResponse)
async def map_event(
    event_id: int,
    alert_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """
    Map a security event to relevant compliance controls.
    Automatically collects evidence and creates mapping records.
    """
    mappings, evidence_count = compliance_service.map_event_to_controls(
        db, event_id=event_id, alert_id=alert_id
    )

    return MappingResponse(
        event_id=event_id,
        alert_id=alert_id,
        controls_mapped=len(mappings),
        mappings=mappings,
        evidence_collected=evidence_count,
        message=f"Successfully mapped event {event_id} to {len(mappings)} controls"
    )


# ─── Compliance Status ─────────────────────────────────────────────────────────

@router.get("/status", response_model=ComplianceStatusResponse)
async def get_compliance_status(db: Session = Depends(get_db)):
    """
    Get compliance coverage percentage for all frameworks.
    Shows how many controls have supporting evidence.
    """
    result = compliance_service.get_compliance_status(db)
    return ComplianceStatusResponse(**result)


# ─── Evidence ──────────────────────────────────────────────────────────────────

@router.get("/evidence", response_model=List[EvidenceResponse])
async def list_evidence(
    framework: Optional[str] = None,
    control_id: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List collected compliance evidence records"""
    query = db.query(ComplianceEvidence)

    if framework:
        fw = db.query(ComplianceFramework).filter_by(code=framework).first()
        if fw:
            query = query.filter_by(framework_id=fw.id)

    if control_id:
        ctrl = db.query(ComplianceControl).filter_by(control_id=control_id).first()
        if ctrl:
            query = query.filter_by(control_id=ctrl.id)

    return query.order_by(ComplianceEvidence.collected_at.desc()).limit(limit).all()


# ─── Reports ───────────────────────────────────────────────────────────────────

@router.post("/reports/generate", response_model=ReportResponse)
async def generate_report(
    request: ReportRequest,
    db: Session = Depends(get_db)
):
    """
    Generate a compliance report for the specified framework.
    Calculates coverage, identifies gaps, and lists evidence.
    """
    report = compliance_service.generate_report(
        db,
        framework_code=request.framework.value,
        time_period_hours=request.time_period_hours
    )

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Framework '{request.framework.value}' not found"
        )

    return report


@router.get("/reports", response_model=List[ReportResponse])
async def list_reports(
    framework: Optional[str] = None,
    limit: int = 20,
    db: Session = Depends(get_db)
):
    """List previously generated compliance reports"""
    query = db.query(ComplianceReport)

    if framework:
        query = query.filter_by(framework_code=framework)

    return query.order_by(ComplianceReport.generated_at.desc()).limit(limit).all()
