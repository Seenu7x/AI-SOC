"""
Compliance Mapping Database Models
Supports NIST CSF, ISO 27001, SOC 2, GDPR frameworks
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey, JSON
from sqlalchemy.sql import func
from app.db.session import Base


class ComplianceFramework(Base):
    """Compliance framework (NIST CSF, ISO 27001, SOC 2, GDPR)"""
    __tablename__ = "compliance_frameworks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)       # e.g. "NIST CSF"
    code = Column(String(50),  nullable=False, unique=True)       # e.g. "nist_csf"
    version = Column(String(20))                                   # e.g. "1.1"
    description = Column(Text)
    category = Column(String(50))                                  # security, privacy, both

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ComplianceControl(Base):
    """Individual control within a framework"""
    __tablename__ = "compliance_controls"

    id = Column(Integer, primary_key=True, index=True)
    framework_id = Column(Integer, ForeignKey("compliance_frameworks.id"), nullable=False)

    control_id = Column(String(50),  nullable=False, index=True)  # e.g. "ID.AM-1"
    title = Column(String(300), nullable=False)
    description = Column(Text)
    category = Column(String(100))                                 # function / domain
    subcategory = Column(String(100))

    # What event types / conditions trigger this control
    related_event_types = Column(JSON, default=list)              # ["network","login"]
    triggers_on_anomaly = Column(Boolean, default=False)
    severity_threshold = Column(String(20))                       # "low","medium","high","critical"

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ControlMapping(Base):
    """Links a security event or alert to compliance controls"""
    __tablename__ = "control_mappings"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, index=True)
    alert_id = Column(Integer, index=True)

    control_id = Column(Integer, ForeignKey("compliance_controls.id"), nullable=False)
    framework_id = Column(Integer, ForeignKey("compliance_frameworks.id"), nullable=False)

    # Why was this mapping created
    mapping_reason = Column(Text)
    confidence_score = Column(Float, default=1.0)
    is_anomaly_trigger = Column(Boolean, default=False)

    mapped_at = Column(DateTime(timezone=True), server_default=func.now())


class ComplianceEvidence(Base):
    """Audit evidence collected from security events / alerts"""
    __tablename__ = "compliance_evidence"

    id = Column(Integer, primary_key=True, index=True)
    control_id = Column(Integer, ForeignKey("compliance_controls.id"), nullable=False)
    framework_id = Column(Integer, ForeignKey("compliance_frameworks.id"), nullable=False)

    evidence_type = Column(String(50))     # "event", "alert", "manual"
    event_id = Column(Integer, index=True)
    alert_id = Column(Integer, index=True)

    title = Column(String(300))
    description = Column(Text)
    status = Column(String(30), default="compliant")  # compliant, non_compliant, partial, pending

    collected_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ComplianceReport(Base):
    """Generated compliance report records"""
    __tablename__ = "compliance_reports"

    id = Column(Integer, primary_key=True, index=True)
    framework_id = Column(Integer, ForeignKey("compliance_frameworks.id"), nullable=False)

    title = Column(String(200), nullable=False)
    framework_code = Column(String(50))

    # Summary metrics
    total_controls = Column(Integer, default=0)
    controls_with_evidence = Column(Integer, default=0)
    compliance_percentage = Column(Float, default=0.0)
    total_events_analyzed = Column(Integer, default=0)
    total_anomalies = Column(Integer, default=0)
    total_alerts = Column(Integer, default=0)

    # Report content (JSON)
    report_data = Column(JSON)

    time_period_hours = Column(Integer, default=24)
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
