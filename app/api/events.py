"""
API routes for security events
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.db.session import get_db
from app.models.models import SecurityEvent
from app.schemas.schemas import (
    SecurityEventCreate,
    SecurityEventResponse,
    BulkEventCreate,
    BulkEventResponse,
    EventStatistics
)
from app.services.anomaly_detection import anomaly_service
from app.services.compliance_service import compliance_service
from app.core.auth import require_auth, TokenData
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/", response_model=SecurityEventResponse, status_code=status.HTTP_201_CREATED)
async def create_event(
    event: SecurityEventCreate,
    db: Session = Depends(get_db),
    _auth: TokenData = Depends(require_auth),
):
    """
    Create a new security event and check for anomalies
    """
    try:
        # Create event
        db_event = SecurityEvent(
            event_type=event.event_type,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            src_port=event.src_port,
            dst_port=event.dst_port,
            protocol=event.protocol,
            bytes_sent=event.bytes_sent,
            bytes_received=event.bytes_received,
            duration=event.duration,
            packet_count=event.packet_count,
            username=event.username,
            user_agent=event.user_agent,
            action=event.action,
            resource=event.resource,
            description=event.description,
            raw_log=event.raw_log,
            # Behavioral features from log agent
            request_rate  = getattr(event, 'request_rate',  0.0)  or 0.0,
            deny_rate     = getattr(event, 'deny_rate',     0.0)  or 0.0,
            inter_arrival = getattr(event, 'inter_arrival', 60.0) or 60.0,
        )
        
        # Check for anomaly — pass all 7 features
        event_data = {
            'event_type':     str(event.event_type),
            'bytes_sent':     event.bytes_sent,
            'bytes_received': event.bytes_received,
            'duration':       event.duration,
            'packet_count':   event.packet_count,
            'request_rate':   getattr(event, 'request_rate',  0.0)  or 0.0,
            'deny_rate':      getattr(event, 'deny_rate',     0.0)  or 0.0,
            'inter_arrival':  getattr(event, 'inter_arrival', 60.0) or 60.0,
        }
        
        is_anomaly, score, severity, explanation = anomaly_service.predict(event_data)
        
        db_event.is_anomaly = is_anomaly
        db_event.anomaly_score = score
        db_event.model_version = anomaly_service.model_version
        
        db.add(db_event)
        db.commit()
        db.refresh(db_event)
        
        # Create alert if anomaly detected
        alert_id = None
        if is_anomaly:
            alert = anomaly_service.create_alert_from_anomaly(
                db=db,
                event_id=db_event.id,
                event_type=event.event_type,
                score=score,
                severity=severity,
                explanation=explanation
            )
            alert_id = alert.id
            logger.warning(f"Anomaly detected in event {db_event.id}: {explanation}")
        
        # AUTOMATIC COMPLIANCE MAPPING
        compliance_service.map_event_to_controls(db, event_id=db_event.id, alert_id=alert_id)
        
        return db_event
        
    except Exception as e:
        logger.error(f"Error creating event: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating event: {str(e)}"
        )


@router.post("/bulk", response_model=BulkEventResponse)
async def create_events_bulk(
    bulk_request: BulkEventCreate,
    db: Session = Depends(get_db),
    _auth: TokenData = Depends(require_auth),
):
    """
    Create multiple security events in bulk
    """
    start_time = datetime.now()
    successful = 0
    failed = 0
    anomalies = 0
    errors = []
    
    try:
        for idx, event in enumerate(bulk_request.events):
            try:
                # Create event
                db_event = SecurityEvent(
                    event_type=event.event_type,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    src_port=event.src_port,
                    dst_port=event.dst_port,
                    protocol=event.protocol,
                    bytes_sent=event.bytes_sent,
                    bytes_received=event.bytes_received,
                    duration=event.duration,
                    packet_count=event.packet_count,
                    username=event.username,
                    user_agent=event.user_agent,
                    action=event.action,
                    resource=event.resource,
                    description=event.description,
                    raw_log=event.raw_log,
                    # Behavioral features
                    request_rate  = getattr(event, 'request_rate',  0.0)  or 0.0,
                    deny_rate     = getattr(event, 'deny_rate',     0.0)  or 0.0,
                    inter_arrival = getattr(event, 'inter_arrival', 60.0) or 60.0,
                )
                
                # Pass all 7 features to ML
                event_data = {
                    'event_type':     str(event.event_type),
                    'bytes_sent':     event.bytes_sent,
                    'bytes_received': event.bytes_received,
                    'duration':       event.duration,
                    'packet_count':   event.packet_count,
                    'request_rate':   getattr(event, 'request_rate',  0.0)  or 0.0,
                    'deny_rate':      getattr(event, 'deny_rate',     0.0)  or 0.0,
                    'inter_arrival':  getattr(event, 'inter_arrival', 60.0) or 60.0,
                }
                
                is_anomaly, score, severity, explanation = anomaly_service.predict(event_data)
                
                db_event.is_anomaly = is_anomaly
                db_event.anomaly_score = score
                db_event.model_version = anomaly_service.model_version
                
                db.add(db_event)
                db.flush()
                
                if is_anomaly:
                    anomalies += 1
                    alert = anomaly_service.create_alert_from_anomaly(
                        db=db,
                        event_id=db_event.id,
                        event_type=event.event_type,
                        score=score,
                        severity=severity,
                        explanation=explanation
                    )
                    # Automatic compliance mapping for anomaly
                    compliance_service.map_event_to_controls(db, event_id=db_event.id, alert_id=alert.id)
                else:
                    # Automatic compliance mapping for normal event
                    compliance_service.map_event_to_controls(db, event_id=db_event.id)
                
                successful += 1
                
            except Exception as e:
                failed += 1
                errors.append(f"Event {idx}: {str(e)}")
                logger.error(f"Error processing event {idx}: {e}")
        
        db.commit()
        processing_time = (datetime.now() - start_time).total_seconds()
        
        return BulkEventResponse(
            total_events=len(bulk_request.events),
            successful=successful,
            failed=failed,
            anomalies_detected=anomalies,
            processing_time_seconds=processing_time,
            errors=errors
        )
        
    except Exception as e:
        logger.error(f"Error in bulk creation: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating events: {str(e)}"
        )


@router.get("/", response_model=List[SecurityEventResponse])
async def get_events(
    skip: int = 0,
    limit: int = 100,
    event_type: Optional[str] = None,
    anomalies_only: bool = False,
    db: Session = Depends(get_db)
):
    """
    Get list of security events with optional filters
    """
    query = db.query(SecurityEvent)
    
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    
    if anomalies_only:
        query = query.filter(SecurityEvent.is_anomaly == True)
    
    query = query.order_by(SecurityEvent.timestamp.desc())
    events = query.offset(skip).limit(limit).all()
    
    return events


@router.get("/{event_id}", response_model=SecurityEventResponse)
async def get_event(
    event_id: int,
    db: Session = Depends(get_db)
):
    """
    Get a specific security event by ID
    """
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event {event_id} not found"
        )
    
    return event


@router.get("/statistics/summary", response_model=EventStatistics)
async def get_event_statistics(
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """
    Get event statistics for the specified time period
    """
    time_threshold = datetime.now() - timedelta(hours=hours)
    
    events = db.query(SecurityEvent).filter(
        SecurityEvent.timestamp >= time_threshold
    ).all()
    
    total_events = len(events)
    anomaly_count = sum(1 for e in events if e.is_anomaly)
    
    # Count by type
    events_by_type = {}
    for event in events:
        event_type = event.event_type.value
        events_by_type[event_type] = events_by_type.get(event_type, 0) + 1
    
    return EventStatistics(
        total_events=total_events,
        events_by_type=events_by_type,
        anomaly_count=anomaly_count,
        anomaly_rate=anomaly_count / total_events if total_events > 0 else 0,
        time_range={
            "start": time_threshold.isoformat(),
            "end": datetime.now().isoformat(),
            "hours": hours
        }
    )


@router.delete("/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_event(
    event_id: int,
    db: Session = Depends(get_db),
    _auth: TokenData = Depends(require_auth),
):
    """
    Delete a security event (use with caution - for testing only)
    """
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event {event_id} not found"
        )
    
    db.delete(event)
    db.commit()
    
    return None
