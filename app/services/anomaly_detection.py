"""
Anomaly Detection Service — Redesigned
========================================
Dual Isolation-Forest models:
  • auth_model  — trained on login events only
  • net_model   — trained on network + system events

Feature set (7 base + 3 derived = 10 total):
  bytes_sent, bytes_received, duration, packet_count,
  request_rate, deny_rate, inter_arrival
  → total_bytes, bytes_per_second, bytes_per_packet (derived)

Contamination: 0.01 (1 %) — reduces false positives.
"""
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.models import SecurityEvent, MLModel, Alert, EventType
from app.schemas.schemas import AlertSeverity
import logging

logger = logging.getLogger(__name__)
settings = get_settings()

# Base features shared by both models
BASE_FEATURES = [
    'bytes_sent', 'bytes_received', 'duration', 'packet_count',
    'request_rate', 'deny_rate', 'inter_arrival',
]


class AnomalyDetectionService:
    """Dual-model anomaly detection: one for auth events, one for network/system."""

    def __init__(self):
        self.model_path = Path(settings.model_path)
        self.model_path.mkdir(parents=True, exist_ok=True)

        # Auth model (login events)
        self.auth_model = None
        self.auth_scaler = None

        # Network/system model
        self.net_model = None
        self.net_scaler = None

        self.model_version: Optional[str] = None
        self.feature_names = BASE_FEATURES

        self._load_latest_model()

    # ── feature engineering ────────────────────────────────────────────────────

    def _extract_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Build final feature matrix from raw event data."""
        # Fill any missing behavioral columns with safe defaults
        for col, default in [('request_rate', 0.0), ('deny_rate', 0.0), ('inter_arrival', 60.0)]:
            if col not in data.columns:
                data[col] = default

        features = data[BASE_FEATURES].copy().fillna(0)

        # Derived features
        features['total_bytes']      = features['bytes_sent'] + features['bytes_received']
        features['bytes_per_second'] = features['total_bytes'] / (features['duration'] + 1)
        features['bytes_per_packet'] = features['total_bytes'] / (features['packet_count'] + 1)
        # Burst indicator: high request_rate AND high deny_rate
        features['burst_score']      = features['request_rate'] * features['deny_rate']

        return features

    # ── model persistence ──────────────────────────────────────────────────────

    def _model_files(self, kind: str):
        """Return (model_file, scaler_file) paths for 'auth' or 'net'."""
        return (
            self.model_path / f"{kind}_model.joblib",
            self.model_path / f"{kind}_scaler.joblib",
        )

    def _load_latest_model(self) -> bool:
        loaded = False
        for kind, attr_m, attr_s in [
            ('auth', 'auth_model', 'auth_scaler'),
            ('net',  'net_model',  'net_scaler'),
        ]:
            mf, sf = self._model_files(kind)
            if mf.exists() and sf.exists():
                try:
                    setattr(self, attr_m, joblib.load(mf))
                    setattr(self, attr_s, joblib.load(sf))
                    loaded = True
                    logger.info(f"Loaded {kind} model")
                except Exception as e:
                    logger.error(f"Error loading {kind} model: {e}")

        version_file = self.model_path / "version.txt"
        if version_file.exists():
            self.model_version = version_file.read_text().strip()
        return loaded

    # ── training ───────────────────────────────────────────────────────────────

    def train_model(
        self,
        db: Session,
        contamination: float = 0.01,   # lowered from 0.05
        n_estimators: int = 100,
    ) -> Dict:
        """
        Train separate Isolation Forest models for auth and network events.
        Only events with known-good labels (action != 'alert') are used for baseline.
        """
        try:
            all_events = db.query(SecurityEvent).all()
            if len(all_events) < settings.min_training_samples:
                return {
                    "status": "error",
                    "message": (
                        f"Need at least {settings.min_training_samples} events, "
                        f"found {len(all_events)}"
                    ),
                }

            def to_df(events):
                return pd.DataFrame([{
                    'bytes_sent':     e.bytes_sent    or 0,
                    'bytes_received': e.bytes_received or 0,
                    'duration':       e.duration      or 0.0,
                    'packet_count':   e.packet_count  or 0,
                    'request_rate':   e.request_rate  if e.request_rate  is not None else 0.0,
                    'deny_rate':      e.deny_rate     if e.deny_rate     is not None else 0.0,
                    'inter_arrival':  e.inter_arrival if e.inter_arrival is not None else 60.0,
                } for e in events])

            # Split by event type - fixed filtering logic
            auth_events = [e for e in all_events if "login" in str(e.event_type).lower()]
            net_events  = [e for e in all_events if "login" not in str(e.event_type).lower()]

            self.model_version = f"v{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            start = datetime.now()
            trained = []

            for kind, events, attr_m, attr_s in [
                ('auth', auth_events, 'auth_model', 'auth_scaler'),
                ('net',  net_events,  'net_model',  'net_scaler'),
            ]:
                if len(events) < max(5, settings.min_training_samples // 4):
                    logger.warning(f"Skipping {kind} model — only {len(events)} events")
                    continue

                df = to_df(events)
                features = self._extract_features(df)

                scaler = StandardScaler()
                X = scaler.fit_transform(features)

                model = IsolationForest(
                    n_estimators=n_estimators,
                    contamination=contamination,
                    random_state=42,
                    n_jobs=-1,
                )
                model.fit(X)

                mf, sf = self._model_files(kind)
                joblib.dump(model, mf)
                joblib.dump(scaler, sf)
                setattr(self, attr_m, model)
                setattr(self, attr_s, scaler)
                trained.append(f"{kind}({len(events)} samples)")
                logger.info(f"Trained {kind} model on {len(events)} events")

            if not trained:
                return {"status": "error", "message": "No sub-models could be trained"}

            (self.model_path / "version.txt").write_text(self.model_version)
            training_time = (datetime.now() - start).total_seconds()

            # Record in DB
            db.query(MLModel).update({MLModel.is_active: False})
            db.add(MLModel(
                model_name="Dual Isolation Forest",
                model_version=self.model_version,
                model_type="dual_isolation_forest",
                training_samples=len(all_events),
                training_features=str(BASE_FEATURES),
                contamination_rate=contamination,
                file_path=str(self.model_path),
                is_active=True,
                trained_at=datetime.now(),
                deployed_at=datetime.now(),
            ))
            db.commit()

            return {
                "status": "success",
                "model_version": self.model_version,
                "training_samples": len(all_events),
                "features": BASE_FEATURES,
                "training_time_seconds": training_time,
                "message": f"Trained: {', '.join(trained)}",
            }

        except Exception as e:
            logger.error(f"Training error: {e}")
            db.rollback()
            return {"status": "error", "message": str(e)}

    # ── implementation ─────────────────────────────────────────────────────────

    def re_score_past_events(self, db: Session, limit: int = 500) -> Dict:
        """
        Re-evaluate the last N events using the current model version.
        Clears stale alerts where the AI now sees 'Normal' behavior.
        """
        if self.auth_model is None and self.net_model is None:
            return {"status": "error", "message": "No model loaded to perform re-scoring"}

        try:
            # Fetch last N events
            events = db.query(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(limit).all()
            updated_count = 0
            cleared_alerts = 0
            new_alerts = 0

            for event in events:
                old_is_anomaly = event.is_anomaly
                
                # Predict using CURRENT model
                event_data = {
                    'event_type':     str(event.event_type),
                    'bytes_sent':     event.bytes_sent,
                    'bytes_received': event.bytes_received,
                    'duration':       event.duration,
                    'packet_count':   event.packet_count,
                    'request_rate':   event.request_rate or 0.0,
                    'deny_rate':      event.deny_rate or 0.0,
                    'inter_arrival':  event.inter_arrival or 60.0,
                }
                is_anomaly, score, severity, explanation = self.predict(event_data)
                
                # Update DB if changed
                event.is_anomaly = is_anomaly
                event.anomaly_score = score
                event.model_version = self.model_version
                updated_count += 1

                # Sync Alerts
                if old_is_anomaly and not is_anomaly:
                    # Clear stale alerts
                    db.query(Alert).filter(Alert.event_id == event.id).delete()
                    cleared_alerts += 1
                elif not old_is_anomaly and is_anomaly:
                    # Create new alert for newly discovered anomaly
                    self.create_alert_from_anomaly(db, event.id, event.event_type, score, severity, explanation)
                    new_alerts += 1

            db.commit()
            return {
                "status": "success",
                "updated_events": updated_count,
                "cleared_alerts": cleared_alerts,
                "new_alerts": new_alerts,
                "model_version": self.model_version
            }

        except Exception as e:
            logger.error(f"Re-score error: {e}")
            db.rollback()
            return {"status": "error", "message": str(e)}

    # ── prediction ─────────────────────────────────────────────────────────────

    def predict(self, event_data: Dict) -> Tuple[bool, float, AlertSeverity, str]:
        """
        Route to the correct sub-model based on event_type.
        Returns (is_anomaly, score, severity, explanation).
        """
        event_type = str(event_data.get('event_type', 'network'))
        is_auth    = 'login' in event_type

        model  = self.auth_model  if is_auth else self.net_model
        scaler = self.auth_scaler if is_auth else self.net_scaler
        kind   = 'auth' if is_auth else 'net'

        if model is None or scaler is None:
            logger.warning(f"No {kind} model loaded — event treated as normal")
            return False, 0.1185, AlertSeverity.LOW, "Model not trained"

        try:
            row = {
                'bytes_sent':     event_data.get('bytes_sent',     0),
                'bytes_received': event_data.get('bytes_received', 0),
                'duration':       event_data.get('duration',       0.0),
                'packet_count':   event_data.get('packet_count',   0),
                'request_rate':   event_data.get('request_rate',   0.0),
                'deny_rate':      event_data.get('deny_rate',      0.0),
                'inter_arrival':  event_data.get('inter_arrival',  60.0),
            }
            df = pd.DataFrame([row])
            features = self._extract_features(df)
            X = scaler.transform(features)

            score       = float(self.net_model.decision_function(X)[0]) if not is_auth \
                         else float(self.auth_model.decision_function(X)[0])
            
            # Prediction from IF (-1 is anomaly, 1 is normal)
            if_prediction = (model.predict(X)[0] == -1)
            
            # Safeguard: Only flag as anomaly if IF says so AND score is negative
            # This prevents false positives on 'Normal' events that are just slightly unusual.
            prediction = if_prediction and (score < 0)

            if score < -0.10:
                severity    = AlertSeverity.CRITICAL
                explanation = "Highly unusual behaviour — extreme deviation from baseline"
            elif score < -0.07:
                severity    = AlertSeverity.HIGH
                explanation = "Significant anomaly — requires immediate attention"
            elif score < -0.04:
                severity    = AlertSeverity.MEDIUM
                explanation = "Moderate anomaly — should be investigated"
            else:
                severity    = AlertSeverity.LOW
                explanation = "Minor or no anomaly — within expected parameters"

            if not prediction:
                severity    = AlertSeverity.LOW
                explanation = "Normal behaviour — within baseline"

            return prediction, score, severity, explanation

        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return False, 0.0, AlertSeverity.LOW, f"Prediction error: {e}"

    # ── helpers ────────────────────────────────────────────────────────────────

    def get_model_info(self) -> Optional[Dict]:
        if self.auth_model is None and self.net_model is None:
            return None
        return {
            "model_version": self.model_version,
            "model_type": "Dual Isolation Forest",
            "features": BASE_FEATURES,
            "is_loaded": True,
            "auth_model_ready": self.auth_model is not None,
            "net_model_ready":  self.net_model  is not None,
        }

    def create_alert_from_anomaly(
        self,
        db: Session,
        event_id: int,
        event_type,
        score: float,
        severity: AlertSeverity,
        explanation: str,
    ) -> Alert:
        alert = Alert(
            title=f"Anomaly Detected — {str(event_type).upper()}",
            description=explanation,
            severity=severity,
            event_id=event_id,
            event_type=event_type,
            anomaly_score=score,
            confidence=min(abs(score), 1.0),
            detection_method="dual_isolation_forest",
            model_version=self.model_version,
            status="open",
            remediation_steps=self._get_remediation_steps(severity, str(event_type)),
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        logger.info(f"Alert created: {alert.id} — {alert.title}")
        return alert

    def _get_remediation_steps(self, severity: AlertSeverity, event_type: str) -> str:
        steps = {
            AlertSeverity.CRITICAL: [
                "1. Immediately isolate affected systems",
                "2. Notify security team and management",
                "3. Initiate incident response protocol",
                "4. Preserve evidence for forensic analysis",
                "5. Monitor for lateral movement",
            ],
            AlertSeverity.HIGH: [
                "1. Investigate the source and destination systems",
                "2. Review recent user activity and access logs",
                "3. Check for indicators of compromise",
                "4. Consider temporary access restrictions",
                "5. Document findings for follow-up",
            ],
            AlertSeverity.MEDIUM: [
                "1. Review event details and context",
                "2. Correlate with other security events",
                "3. Verify with system owner if behaviour is expected",
                "4. Add to watchlist for monitoring",
                "5. Update detection rules if false positive",
            ],
            AlertSeverity.LOW: [
                "1. Log for future reference",
                "2. Review during regular security assessment",
                "3. Consider tuning detection thresholds",
                "4. No immediate action required",
            ],
        }
        return "\n".join(steps.get(severity, steps[AlertSeverity.LOW]))


# Global service instance
anomaly_service = AnomalyDetectionService()
