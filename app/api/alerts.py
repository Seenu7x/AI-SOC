"""
API routes for security alerts
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.db.session import get_db
from app.models.models import Alert
from app.schemas.schemas import (
    AlertResponse,
    AlertUpdate,
    AlertStatistics,
    AlertSeverity
)
from app.core.auth import require_jwt, TokenData
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/", response_model=List[AlertResponse])
async def get_alerts(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[AlertSeverity] = None,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Get list of alerts with optional filters
    """
    query = db.query(Alert)
    
    if severity:
        query = query.filter(Alert.severity == severity)
    
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    
    query = query.order_by(Alert.timestamp.desc())
    alerts = query.offset(skip).limit(limit).all()
    
    return alerts


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):
    """
    Get a specific alert by ID
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found"
        )
    
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    alert_update: AlertUpdate,
    db: Session = Depends(get_db),
    _auth: TokenData = Depends(require_jwt),
):
    """
    Update an alert (status, assignment, notes)
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found"
        )
    
    # Update fields
    if alert_update.status is not None:
        alert.status = alert_update.status
        if alert_update.status in ["resolved", "false_positive"]:
            alert.resolved_at = datetime.now()
    
    if alert_update.assigned_to is not None:
        alert.assigned_to = alert_update.assigned_to
    
    if alert_update.notes is not None:
        if alert.notes:
            alert.notes += f"\n\n[{datetime.now().isoformat()}]\n{alert_update.notes}"
        else:
            alert.notes = f"[{datetime.now().isoformat()}]\n{alert_update.notes}"
    
    alert.updated_at = datetime.now()
    
    db.commit()
    db.refresh(alert)
    
    logger.info(f"Alert {alert_id} updated")
    return alert


@router.get("/statistics/summary", response_model=AlertStatistics)
async def get_alert_statistics(
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """
    Get alert statistics for the specified time period
    """
    time_threshold = datetime.now() - timedelta(hours=hours)
    
    alerts = db.query(Alert).filter(
        Alert.timestamp >= time_threshold
    ).all()
    
    total_alerts = len(alerts)
    
    # Count by severity
    alerts_by_severity = {
        "critical": sum(1 for a in alerts if a.severity == AlertSeverity.CRITICAL),
        "high": sum(1 for a in alerts if a.severity == AlertSeverity.HIGH),
        "medium": sum(1 for a in alerts if a.severity == AlertSeverity.MEDIUM),
        "low": sum(1 for a in alerts if a.severity == AlertSeverity.LOW)
    }
    
    # Count by status
    open_alerts = sum(1 for a in alerts if a.status == "open")
    resolved_alerts = sum(1 for a in alerts if a.status in ["resolved", "false_positive"])
    
    # Calculate average resolution time
    resolved = [a for a in alerts if a.resolved_at]
    avg_resolution_time = None
    if resolved:
        resolution_times = [
            (a.resolved_at - a.created_at).total_seconds() / 3600
            for a in resolved if a.resolved_at and a.created_at
        ]
        if resolution_times:
            avg_resolution_time = sum(resolution_times) / len(resolution_times)
    
    return AlertStatistics(
        total_alerts=total_alerts,
        alerts_by_severity=alerts_by_severity,
        open_alerts=open_alerts,
        resolved_alerts=resolved_alerts,
        avg_resolution_time=avg_resolution_time
    )


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    _auth: TokenData = Depends(require_jwt),
):
    """
    Delete an alert (use with caution - for testing only)
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found"
        )
    
    db.delete(alert)
    db.commit()
    
    return None
