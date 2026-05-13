"""
Compliance Mapping Service
Seeds control libraries and maps events/alerts to compliance controls
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.compliance import (
    ComplianceFramework, ComplianceControl, ControlMapping,
    ComplianceEvidence, ComplianceReport
)
from app.models.models import SecurityEvent, Alert

logger = logging.getLogger(__name__)

# ─── Built-in control libraries ────────────────────────────────────────────────

FRAMEWORKS = [
    {
        "name": "NIST Cybersecurity Framework",
        "code": "nist_csf",
        "version": "1.1",
        "description": "Framework for improving critical infrastructure cybersecurity",
        "category": "security",
    },
    {
        "name": "ISO/IEC 27001:2022",
        "code": "iso_27001",
        "version": "2022",
        "description": "International standard for information security management",
        "category": "security",
    },
    {
        "name": "SOC 2 Type II",
        "code": "soc2",
        "version": "2017",
        "description": "AICPA service organization control reporting framework",
        "category": "security",
    },
    {
        "name": "GDPR",
        "code": "gdpr",
        "version": "2018",
        "description": "EU General Data Protection Regulation",
        "category": "privacy",
    },
]

CONTROLS = {
    "nist_csf": [
        {
            "control_id": "ID.AM-1",
            "title": "Physical devices and systems within the organization are inventoried",
            "description": "Maintain an accurate and up-to-date inventory of all physical devices.",
            "category": "Identify",
            "subcategory": "Asset Management",
            "related_event_types": ["network", "system"],
            "triggers_on_anomaly": False,
        },
        {
            "control_id": "ID.AM-2",
            "title": "Software platforms and applications within the organization are inventoried",
            "description": "Maintain a current inventory of software platforms and applications.",
            "category": "Identify",
            "subcategory": "Asset Management",
            "related_event_types": ["application", "system"],
            "triggers_on_anomaly": False,
        },
        {
            "control_id": "PR.AC-1",
            "title": "Identities and credentials are issued, managed, verified and revoked",
            "description": "Manage identities and credentials for authorized users and services.",
            "category": "Protect",
            "subcategory": "Identity Management",
            "related_event_types": ["login"],
            "triggers_on_anomaly": True,
            "severity_threshold": "medium",
        },
        {
            "control_id": "PR.AC-3",
            "title": "Remote access is managed",
            "description": "Remote access to organizational resources is managed and monitored.",
            "category": "Protect",
            "subcategory": "Access Control",
            "related_event_types": ["network", "login"],
            "triggers_on_anomaly": True,
            "severity_threshold": "medium",
        },
        {
            "control_id": "PR.DS-1",
            "title": "Data-at-rest is protected",
            "description": "Protect data at rest using encryption and access controls.",
            "category": "Protect",
            "subcategory": "Data Security",
            "related_event_types": ["file_access"],
            "triggers_on_anomaly": True,
            "severity_threshold": "medium",
        },
        {
            "control_id": "DE.AE-1",
            "title": "A baseline of network operations is established and managed",
            "description": "Understand normal network patterns to detect deviations.",
            "category": "Detect",
            "subcategory": "Anomalies and Events",
            "related_event_types": ["network"],
            "triggers_on_anomaly": True,
            "severity_threshold": "low",
        },
        {
            "control_id": "DE.AE-2",
            "title": "Detected events are analyzed to understand attack targets and methods",
            "description": "Analyze detected events to understand the nature of attacks.",
            "category": "Detect",
            "subcategory": "Anomalies and Events",
            "related_event_types": ["network", "login", "file_access", "system", "application"],
            "triggers_on_anomaly": True,
            "severity_threshold": "low",
        },
        {
            "control_id": "DE.CM-1",
            "title": "The network is monitored to detect potential cybersecurity events",
            "description": "Continuous monitoring of network traffic for security events.",
            "category": "Detect",
            "subcategory": "Security Continuous Monitoring",
            "related_event_types": ["network"],
            "triggers_on_anomaly": False,
        },
        {
            "control_id": "DE.CM-7",
            "title": "Monitoring for unauthorized personnel, connections, devices is performed",
            "description": "Monitor for unauthorized activities across the organization.",
            "category": "Detect",
            "subcategory": "Security Continuous Monitoring",
            "related_event_types": ["network", "login", "file_access"],
            "triggers_on_anomaly": True,
            "severity_threshold": "medium",
        },
        {
            "control_id": "RS.AN-1",
            "title": "Notifications from detection systems are investigated",
            "description": "Alerts and notifications from security systems are investigated.",
            "category": "Respond",
            "subcategory": "Analysis",
            "related_event_types": ["network", "login", "system", "application"],
            "triggers_on_anomaly": True,
            "severity_threshold": "low",
        },
        {
            "control_id": "RS.MI-1",
            "title": "Incidents are contained",
            "description": "Incident containment activities are coordinated.",
            "category": "Respond",
            "subcategory": "Mitigation",
            "related_event_types": ["network", "login", "file_access", "system"],
            "triggers_on_anomaly": True,
            "severity_threshold": "high",
        },
    ],
    "iso_27001": [
        {
            "control_id": "A.8.1.1",
            "title": "Inventory of assets",
            "description": "Information and assets associated with information shall be identified.",
            "category": "Asset Management",
            "related_event_types": ["network", "system"],
            "triggers_on_anomaly": False,
        },
        {
            "control_id": "A.9.1.1",
            "title": "Access control policy",
            "description": "An access control policy shall be established and reviewed based on business requirements.",
            "category": "Access Control",
            "related_event_types": ["login"],
            "triggers_on_anomaly": True,
            "severity_threshold": "medium",
        },
        {
            "control_id": "A.9.4.2",
            "title": "Secure log-on procedures",
            "description": "Secure log-on procedures shall be implemented where access control policy requires.",
            "category": "Access Control",
            "related_event_types": ["login"],
            "triggers_on_anomaly": True,
            "severity_threshold": "medium",
        },
        {
            "control_id": "A.12.4.1",
            "title": "Event logging",
            "description": "Event logs recording user activities shall be produced, kept and regularly reviewed.",
            "category": "Operations Security",
            "related_event_types": ["network", "login", "file_access", "system", "application"],
            "triggers_on_anomaly": False,
        },
        {
            "control_id": "A.12.6.1",
            "title": "Management of technical vulnerabilities",
            "description": "Information about technical vulnerabilities shall be obtained and managed.",
            "category": "Operations Security",
            "related_event_types": ["network", "system"],
            "triggers_on_anomaly": True,
            "severity_threshold": "high",
        },
        {
            "control_id": "A.13.1.1",
            "title": "Network controls",
            "description": "Networks shall be managed and controlled to protect information in systems.",
            "category": "Communications Security",
            "related_event_types": ["network"],
            "triggers_on_anomaly": True,
            "severity_threshold": "medium",
        },
        {
            "control_id": "A.16.1.1",
            "title": "Responsibilities and procedures for incident management",
            "description": "Management responsibilities and procedures shall be established for incident response.",
            "category": "Incident Management",
            "related_event_types": ["network", "login", "file_access", "system", "application"],
            "triggers_on_anomaly": True,
            "severity_threshold": "low",
        },
        {
            "control_id": "A.16.1.4",
            "title": "Assessment of and decision on information security events",
            "description": "Information security events shall be assessed and decided if they shall be classified as incidents.",
            "category": "Incident Management",
            "related_event_types": ["network", "login", "file_access", "system", "application"],
            "triggers_on_anomaly": True,
            "severity_threshold": "low",
        },
    ],
    "soc2": [
        {
            "control_id": "CC1.1",
            "title": "COSO Principle 1: Demonstrates commitment to integrity and ethical values",
            "description": "The entity demonstrates a commitment to integrity and ethical values.",
            "category": "Control Environment",
            "related_event_types": ["login", "file_access"],
            "triggers_on_anomaly": False,
        },
        {
            "control_id": "CC6.1",
            "title": "Logical and physical access controls",
            "description": "The entity implements logical access security measures.",
            "category": "Logical and Physical Access Controls",
            "related_event_types": ["login", "file_access"],
            "triggers_on_anomaly": True,
            "severity_threshold": "medium",
        },
        {
            "control_id": "CC6.6",
            "title": "Security measures against threats from outside the boundary",
            "description": "Security measures are implemented to prevent or detect threats from outside the system boundaries.",
            "category": "Logical and Physical Access Controls",
            "related_event_types": ["network"],
            "triggers_on_anomaly": True,
            "severity_threshold": "medium",
        },
        {
            "control_id": "CC6.7",
            "title": "Transmission of data",
            "description": "The entity restricts the transmission and movement of information.",
            "category": "Logical and Physical Access Controls",
            "related_event_types": ["network"],
            "triggers_on_anomaly": True,
            "severity_threshold": "high",
        },
        {
            "control_id": "CC7.1",
            "title": "Detection of new vulnerabilities",
            "description": "The entity uses detection and monitoring procedures to identify changes.",
            "category": "System Operations",
            "related_event_types": ["network", "system"],
            "triggers_on_anomaly": True,
            "severity_threshold": "medium",
        },
        {
            "control_id": "CC7.2",
            "title": "Monitor system components for anomalous behavior",
            "description": "The entity monitors system components for anomalous behavior.",
            "category": "System Operations",
            "related_event_types": ["network", "login", "system", "application"],
            "triggers_on_anomaly": True,
            "severity_threshold": "low",
        },
        {
            "control_id": "CC7.3",
            "title": "Evaluate security events",
            "description": "The entity evaluates security events to determine whether they could impair objectives.",
            "category": "System Operations",
            "related_event_types": ["network", "login", "file_access", "system", "application"],
            "triggers_on_anomaly": True,
            "severity_threshold": "low",
        },
        {
            "control_id": "CC7.4",
            "title": "Respond to identified security incidents",
            "description": "The entity responds to identified security incidents.",
            "category": "System Operations",
            "related_event_types": ["network", "login", "file_access", "system", "application"],
            "triggers_on_anomaly": True,
            "severity_threshold": "medium",
        },
    ],
    "gdpr": [
        {
            "control_id": "Art.5",
            "title": "Principles relating to processing of personal data",
            "description": "Personal data shall be processed lawfully, fairly and in a transparent manner.",
            "category": "Data Processing Principles",
            "related_event_types": ["file_access", "application"],
            "triggers_on_anomaly": True,
            "severity_threshold": "high",
        },
        {
            "control_id": "Art.25",
            "title": "Data protection by design and by default",
            "description": "The controller shall implement data protection principles by design.",
            "category": "Data Protection",
            "related_event_types": ["file_access"],
            "triggers_on_anomaly": False,
        },
        {
            "control_id": "Art.32",
            "title": "Security of processing",
            "description": "Implement appropriate technical and organisational measures to ensure security.",
            "category": "Security",
            "related_event_types": ["network", "login", "file_access", "system"],
            "triggers_on_anomaly": True,
            "severity_threshold": "high",
        },
        {
            "control_id": "Art.33",
            "title": "Notification of personal data breach to supervisory authority",
            "description": "Notify the supervisory authority of personal data breaches within 72 hours.",
            "category": "Breach Notification",
            "related_event_types": ["file_access", "network"],
            "triggers_on_anomaly": True,
            "severity_threshold": "critical",
        },
        {
            "control_id": "Art.35",
            "title": "Data protection impact assessment",
            "description": "Carry out DPIA for high-risk processing activities.",
            "category": "Risk Assessment",
            "related_event_types": ["file_access", "application"],
            "triggers_on_anomaly": True,
            "severity_threshold": "high",
        },
    ],
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class ComplianceService:
    """Handles compliance mapping, evidence collection, and reporting"""

    def seed_frameworks(self, db: Session) -> None:
        """Seed built-in frameworks and controls if not already present"""
        for fw_data in FRAMEWORKS:
            existing = db.query(ComplianceFramework).filter_by(code=fw_data["code"]).first()
            if existing:
                continue

            framework = ComplianceFramework(**fw_data)
            db.add(framework)
            db.flush()

            for ctrl_data in CONTROLS.get(fw_data["code"], []):
                ctrl_data_copy = dict(ctrl_data)
                ctrl_data_copy["framework_id"] = framework.id
                control = ComplianceControl(**ctrl_data_copy)
                db.add(control)

            logger.info(f"Seeded framework: {fw_data['name']}")

        db.commit()
        logger.info("Compliance frameworks seeded successfully")

    def map_event_to_controls(
        self, db: Session, event_id: int, alert_id: Optional[int] = None
    ) -> Tuple[List[Dict], int]:
        """Map a security event (and optionally its alert) to compliance controls"""

        event = db.query(SecurityEvent).filter_by(id=event_id).first()
        if not event:
            return [], 0

        alert = None
        if alert_id:
            alert = db.query(Alert).filter_by(id=alert_id).first()

        event_type_str = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
        is_anomaly = event.is_anomaly or False
        severity = alert.severity.value if alert and hasattr(alert.severity, "value") else "low"

        controls = db.query(ComplianceControl).filter_by(is_active=True).all()

        mappings_created = []
        evidence_count = 0

        for control in controls:
            related_types = control.related_event_types or []
            if event_type_str not in related_types:
                continue

            # Check anomaly trigger condition
            if control.triggers_on_anomaly and not is_anomaly:
                continue

            # Check severity threshold
            if control.severity_threshold and is_anomaly:
                ctrl_level = SEVERITY_ORDER.get(control.severity_threshold, 0)
                event_level = SEVERITY_ORDER.get(severity, 0)
                if event_level < ctrl_level:
                    continue

            # Avoid duplicate mappings
            existing_mapping = db.query(ControlMapping).filter_by(
                event_id=event_id, control_id=control.id
            ).first()
            if existing_mapping:
                continue

            reason = f"Event type '{event_type_str}' matches control scope"
            if is_anomaly:
                reason += f"; anomaly detected (severity={severity})"

            mapping = ControlMapping(
                event_id=event_id,
                alert_id=alert_id,
                control_id=control.id,
                framework_id=control.framework_id,
                mapping_reason=reason,
                confidence_score=0.9 if is_anomaly else 0.7,
                is_anomaly_trigger=is_anomaly,
            )
            db.add(mapping)

            # Collect evidence
            framework = db.query(ComplianceFramework).filter_by(id=control.framework_id).first()
            ev_status = "non_compliant" if is_anomaly and SEVERITY_ORDER.get(severity, 0) >= 2 else "compliant"

            evidence = ComplianceEvidence(
                control_id=control.id,
                framework_id=control.framework_id,
                evidence_type="alert" if alert_id else "event",
                event_id=event_id,
                alert_id=alert_id,
                title=f"Security event {event_id} — {event_type_str}",
                description=reason,
                status=ev_status,
            )
            db.add(evidence)
            evidence_count += 1

            mappings_created.append({
                "control_id": control.control_id,
                "control_title": control.title,
                "framework": framework.code if framework else "unknown",
                "reason": reason,
                "confidence": mapping.confidence_score,
            })

        db.commit()
        return mappings_created, evidence_count

    def get_compliance_status(self, db: Session) -> Dict:
        """Calculate compliance coverage per framework"""
        frameworks = db.query(ComplianceFramework).filter_by(is_active=True).all()
        results = []
        total_evidence = db.query(ComplianceEvidence).count()

        for fw in frameworks:
            controls = db.query(ComplianceControl).filter_by(
                framework_id=fw.id, is_active=True
            ).all()
            total = len(controls)

            controls_covered = 0
            for ctrl in controls:
                has_evidence = db.query(ComplianceEvidence).filter_by(
                    control_id=ctrl.id
                ).first()
                if has_evidence:
                    controls_covered += 1

            pct = round((controls_covered / total * 100), 1) if total > 0 else 0.0

            # Get last update time
            last_evidence = (
                db.query(ComplianceEvidence)
                .filter_by(framework_id=fw.id)
                .order_by(ComplianceEvidence.collected_at.desc())
                .first()
            )
            last_updated = last_evidence.collected_at.isoformat() if last_evidence else None

            results.append({
                "framework_code": fw.code,
                "framework_name": fw.name,
                "total_controls": total,
                "controls_with_evidence": controls_covered,
                "compliance_percentage": pct,
                "last_updated": last_updated,
            })

        overall = (
            sum(r["compliance_percentage"] for r in results) / len(results)
            if results else 0.0
        )

        return {
            "frameworks": results,
            "overall_compliance": round(overall, 1),
            "total_evidence_items": total_evidence,
            "assessment_time": datetime.now().isoformat(),
        }

    def generate_report(
        self, db: Session, framework_code: str, time_period_hours: int = 24
    ) -> Optional[ComplianceReport]:
        """Generate a compliance report for a specific framework"""
        framework = db.query(ComplianceFramework).filter_by(code=framework_code).first()
        if not framework:
            return None

        cutoff = datetime.now() - timedelta(hours=time_period_hours)

        controls = db.query(ComplianceControl).filter_by(
            framework_id=framework.id, is_active=True
        ).all()
        total_controls = len(controls)

        controls_with_evidence = 0
        control_details = []

        for ctrl in controls:
            evidence_items = (
                db.query(ComplianceEvidence)
                .filter_by(control_id=ctrl.id)
                .filter(ComplianceEvidence.collected_at >= cutoff)
                .all()
            )
            has_evidence = len(evidence_items) > 0
            if has_evidence:
                controls_with_evidence += 1

            control_details.append({
                "control_id": ctrl.control_id,
                "title": ctrl.title,
                "category": ctrl.category,
                "evidence_count": len(evidence_items),
                "status": "covered" if has_evidence else "gap",
                "evidence_items": [
                    {
                        "event_id": e.event_id,
                        "alert_id": e.alert_id,
                        "status": e.status,
                        "collected_at": e.collected_at.isoformat(),
                    }
                    for e in evidence_items
                ],
            })

        # Event / anomaly / alert counts in period
        events_in_period = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.created_at >= cutoff)
            .count()
        )
        anomalies_in_period = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.created_at >= cutoff, SecurityEvent.is_anomaly == True)
            .count()
        )
        alerts_in_period = (
            db.query(Alert).filter(Alert.created_at >= cutoff).count()
        )

        compliance_pct = round(
            controls_with_evidence / total_controls * 100, 1
        ) if total_controls > 0 else 0.0

        report_data = {
            "framework": {"name": framework.name, "version": framework.version, "code": framework.code},
            "period": {
                "hours": time_period_hours,
                "from": cutoff.isoformat(),
                "to": datetime.now().isoformat(),
            },
            "summary": {
                "total_controls": total_controls,
                "controls_with_evidence": controls_with_evidence,
                "compliance_percentage": compliance_pct,
                "gaps": total_controls - controls_with_evidence,
            },
            "controls": control_details,
        }

        report = ComplianceReport(
            framework_id=framework.id,
            title=f"{framework.name} Compliance Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            framework_code=framework.code,
            total_controls=total_controls,
            controls_with_evidence=controls_with_evidence,
            compliance_percentage=compliance_pct,
            total_events_analyzed=events_in_period,
            total_anomalies=anomalies_in_period,
            total_alerts=alerts_in_period,
            report_data=report_data,
            time_period_hours=time_period_hours,
        )

        db.add(report)
        db.commit()
        db.refresh(report)
        return report


# Global singleton
compliance_service = ComplianceService()
