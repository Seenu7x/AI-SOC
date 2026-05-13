"""
Pydantic schemas for request/response validation
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, List
from datetime import datetime
from enum import Enum


class EventType(str, Enum):
    """Event types"""
    NETWORK = "network"
    LOGIN = "login"
    FILE_ACCESS = "file_access"
    SYSTEM = "system"
    APPLICATION = "application"


class AlertSeverity(str, Enum):
    """Alert severity"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============== Security Event Schemas ==============

class SecurityEventCreate(BaseModel):
    """Schema for creating a security event"""
    event_type: EventType
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = Field(None, max_length=20)
    
    bytes_sent: int = Field(default=0, ge=0)
    bytes_received: int = Field(default=0, ge=0)
    duration: float = Field(default=0.0, ge=0)
    packet_count: int = Field(default=0, ge=0)
    
    username: Optional[str] = None
    user_agent: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    description: Optional[str] = None
    raw_log: Optional[str] = None

    # Behavioral features — computed by log agent's EventEnricher
    request_rate:  Optional[float] = Field(default=0.0,  ge=0, description="Events/min from this source")
    deny_rate:     Optional[float] = Field(default=0.0,  ge=0, le=1.0, description="Denied-event ratio")
    inter_arrival: Optional[float] = Field(default=60.0, ge=0, description="Seconds since last event from source")
    
    @validator('src_ip', 'dst_ip')
    def validate_ip(cls, v):
        if v and len(v) > 45:
            raise ValueError('IP address too long')
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "event_type": "network",
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.50",
                "src_port": 54321,
                "dst_port": 443,
                "protocol": "TCP",
                "bytes_sent": 1024,
                "bytes_received": 2048,
                "duration": 1.5,
                "packet_count": 15,
                "action": "allow"
            }
        }


class SecurityEventResponse(BaseModel):
    """Schema for security event response"""
    id: int
    timestamp: datetime
    event_type: EventType
    src_ip: str
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    
    bytes_sent: int
    bytes_received: int
    duration: float
    packet_count: int
    request_rate:  Optional[float]
    deny_rate:     Optional[float]
    inter_arrival: Optional[float]

    username: Optional[str]
    action: Optional[str]
    
    is_anomaly: bool
    anomaly_score: Optional[float]
    model_version: Optional[str]
    
    created_at: datetime
    
    class Config:
        from_attributes = True


# ============== Anomaly Detection Schemas ==============

class AnomalyDetectionRequest(BaseModel):
    """Schema for anomaly detection request"""
    event_type: EventType
    src_ip: str
    dst_ip: Optional[str] = None
    bytes_sent: int = Field(ge=0)
    bytes_received: int = Field(ge=0)
    duration: float = Field(ge=0)
    packet_count: int = Field(ge=0)
    
    class Config:
        json_schema_extra = {
            "example": {
                "event_type": "network",
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.50",
                "bytes_sent": 50000,
                "bytes_received": 100000,
                "duration": 120.5,
                "packet_count": 500
            }
        }


class AnomalyDetectionResponse(BaseModel):
    """Schema for anomaly detection response"""
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    severity: AlertSeverity
    model_version: str
    features_used: List[str]
    explanation: str
    
    model_config = {"protected_namespaces": (), "json_schema_extra": {
        "example": {
            "is_anomaly": True,
            "anomaly_score": -0.75,
            "confidence": 0.85,
            "severity": "high",
            "model_version": "v1.0.0",
            "features_used": ["bytes_sent", "bytes_received", "duration", "packet_count"],
            "explanation": "Unusual data transfer pattern detected"
        }
    }}


# ============== Alert Schemas ==============

class AlertCreate(BaseModel):
    """Schema for creating an alert"""
    title: str = Field(..., max_length=200)
    description: Optional[str] = None
    severity: AlertSeverity
    event_id: Optional[int] = None
    event_type: Optional[EventType] = None
    anomaly_score: Optional[float] = None
    confidence: Optional[float] = None
    detection_method: Optional[str] = None


class AlertResponse(BaseModel):
    """Schema for alert response"""
    id: int
    timestamp: datetime
    title: str
    description: Optional[str]
    severity: AlertSeverity
    event_id: Optional[int]
    event_type: Optional[EventType]
    anomaly_score: Optional[float]
    confidence: Optional[float]
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    """Schema for updating an alert"""
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


# ============== ML Model Schemas ==============

class ModelTrainRequest(BaseModel):
    """Schema for model training request"""
    model_type: str = Field(default="isolation_forest", description="Type of ML model")
    contamination_rate: float = Field(default=0.01, ge=0.0, le=0.5)  # 1% — fewer false positives
    n_estimators: int = Field(default=100, ge=10, le=500)
    
    model_config = {"protected_namespaces": (), "json_schema_extra": {
        "example": {
            "model_type": "isolation_forest",
            "contamination_rate": 0.05,
            "n_estimators": 100
        }
    }}


class ModelTrainResponse(BaseModel):
    """Schema for model training response"""
    status: str
    model_version: str
    training_samples: int
    features: List[str]
    training_time_seconds: float
    message: str


class ModelInfoResponse(BaseModel):
    """Schema for model information"""
    model_name: str
    model_version: str
    model_type: str
    is_active: bool
    training_samples: int
    trained_at: Optional[datetime]
    deployed_at: Optional[datetime]
    
    model_config = {"protected_namespaces": (), "from_attributes": True}


# ============== Statistics Schemas ==============

class EventStatistics(BaseModel):
    """Schema for event statistics"""
    total_events: int
    events_by_type: dict
    anomaly_count: int
    anomaly_rate: float
    time_range: dict


class AlertStatistics(BaseModel):
    """Schema for alert statistics"""
    total_alerts: int
    alerts_by_severity: dict
    open_alerts: int
    resolved_alerts: int
    avg_resolution_time: Optional[float]


class SystemHealth(BaseModel):
    """Schema for system health status"""
    status: str
    events_processed: int
    anomalies_detected: int
    alerts_active: int
    model_active: bool
    model_version: Optional[str]
    uptime_seconds: float
    last_event_time: Optional[datetime]


# ============== Bulk Operations ==============

class BulkEventCreate(BaseModel):
    """Schema for bulk event creation"""
    events: List[SecurityEventCreate]
    
    @validator('events')
    def validate_events_count(cls, v):
        if len(v) > 1000:
            raise ValueError('Cannot process more than 1000 events at once')
        if len(v) == 0:
            raise ValueError('At least one event required')
        return v


class BulkEventResponse(BaseModel):
    """Schema for bulk event response"""
    total_events: int
    successful: int
    failed: int
    anomalies_detected: int
    processing_time_seconds: float
    errors: List[str] = []
