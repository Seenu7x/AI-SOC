"""
Database models for security events, alerts, and ML models
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, Enum
from sqlalchemy.sql import func
from app.db.session import Base
import enum


class EventType(str, enum.Enum):
    """Types of security events"""
    NETWORK = "network"
    LOGIN = "login"
    FILE_ACCESS = "file_access"
    SYSTEM = "system"
    APPLICATION = "application"


class AlertSeverity(str, enum.Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(Base):
    """Security event model"""
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    # Event Details
    event_type = Column(Enum(EventType), nullable=False, index=True)
    src_ip = Column(String(45), index=True)  # IPv6 support
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(20))
    
    # Metrics
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    duration = Column(Float, default=0.0)
    packet_count = Column(Integer, default=0)

    # Behavioral features (rate/timing, computed by log agent)
    request_rate  = Column(Float, default=0.0)   # events/min from same source
    deny_rate     = Column(Float, default=0.0)   # denied-ratio from same source
    inter_arrival = Column(Float, default=60.0)  # seconds since last event from source
    
    # User Context
    username = Column(String(100))
    user_agent = Column(String(500))
    
    # Additional Context
    action = Column(String(100))  # e.g., "allow", "deny", "alert"
    resource = Column(String(500))  # file path, URL, etc.
    description = Column(Text)
    raw_log = Column(Text)
    
    # ML Results
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float)
    model_version = Column(String(50))
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class Alert(Base):
    """Security alert model"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    # Alert Details
    title = Column(String(200), nullable=False)
    description = Column(Text)
    severity = Column(Enum(AlertSeverity), nullable=False, index=True)
    
    # Related Event
    event_id = Column(Integer, index=True)
    event_type = Column(Enum(EventType))
    
    # Anomaly Information
    anomaly_score = Column(Float)
    confidence = Column(Float)
    
    # Detection Method
    detection_method = Column(String(100))  # e.g., "isolation_forest", "rule_based"
    model_version = Column(String(50))
    
    # Status
    status = Column(String(20), default="open")  # open, investigating, resolved, false_positive
    assigned_to = Column(String(100))
    
    # Response
    remediation_steps = Column(Text)
    notes = Column(Text)
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    resolved_at = Column(DateTime(timezone=True))


class MLModel(Base):
    """ML model tracking"""
    __tablename__ = "ml_models"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Model Information
    model_name = Column(String(100), nullable=False)
    model_version = Column(String(50), nullable=False, unique=True)
    model_type = Column(String(50))  # e.g., "isolation_forest", "autoencoder"
    
    # Training Details
    training_samples = Column(Integer)
    training_features = Column(Text)  # JSON string of feature names
    contamination_rate = Column(Float)
    
    # Performance Metrics
    accuracy = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    
    # Model File
    file_path = Column(String(500))
    
    # Status
    is_active = Column(Boolean, default=False)
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    trained_at = Column(DateTime(timezone=True))
    deployed_at = Column(DateTime(timezone=True))


class SystemMetrics(Base):
    """System performance metrics"""
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    # Event Processing
    events_processed = Column(Integer, default=0)
    events_per_second = Column(Float, default=0.0)
    
    # Anomaly Detection
    anomalies_detected = Column(Integer, default=0)
    anomaly_rate = Column(Float, default=0.0)
    
    # Alerts
    alerts_generated = Column(Integer, default=0)
    alerts_critical = Column(Integer, default=0)
    alerts_high = Column(Integer, default=0)
    alerts_medium = Column(Integer, default=0)
    alerts_low = Column(Integer, default=0)
    
    # System Performance
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    disk_usage = Column(Float)
    
    # API Performance
    api_requests = Column(Integer, default=0)
    api_errors = Column(Integer, default=0)
    avg_response_time = Column(Float, default=0.0)
