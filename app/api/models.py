"""
API routes for ML model operations
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime

from app.db.session import get_db
from app.models.models import MLModel
from app.schemas.schemas import (
    ModelTrainRequest,
    ModelTrainResponse,
    ModelInfoResponse,
    AnomalyDetectionRequest,
    AnomalyDetectionResponse
)
from app.services.anomaly_detection import anomaly_service
from app.core.auth import require_jwt, TokenData
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/train", response_model=ModelTrainResponse)
async def train_model(
    request: ModelTrainRequest,
    db: Session = Depends(get_db),
    _auth: TokenData = Depends(require_jwt),
):
    """
    Train a new anomaly detection model on historical data
    """
    logger.info(f"Starting model training with contamination={request.contamination_rate}")
    
    result = anomaly_service.train_model(
        db=db,
        contamination=request.contamination_rate,
        n_estimators=request.n_estimators
    )
    
    if result["status"] == "error":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["message"]
        )
    
    return ModelTrainResponse(**result)


@router.post("/predict", response_model=AnomalyDetectionResponse)
async def predict_anomaly(
    request: AnomalyDetectionRequest,
    db: Session = Depends(get_db)
):
    """
    Predict if an event is anomalous without storing it
    """
    event_data = {
        'bytes_sent': request.bytes_sent,
        'bytes_received': request.bytes_received,
        'duration': request.duration,
        'packet_count': request.packet_count
    }
    
    is_anomaly, score, severity, explanation = anomaly_service.predict(event_data)
    
    model_info = anomaly_service.get_model_info()
    
    if not model_info:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not trained. Please train a model first."
        )
    
    return AnomalyDetectionResponse(
        is_anomaly=is_anomaly,
        anomaly_score=score,
        confidence=min(abs(score), 1.0),
        severity=severity,
        model_version=model_info["model_version"],
        features_used=model_info["features"],
        explanation=explanation
    )


@router.get("/info", response_model=ModelInfoResponse)
async def get_model_info(
    db: Session = Depends(get_db)
):
    """
    Get information about the active model
    """
    active_model = db.query(MLModel).filter(
        MLModel.is_active == True
    ).first()
    
    if not active_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active model found. Please train a model first."
        )
    
    return active_model


@router.get("/versions")
async def get_model_versions(
    db: Session = Depends(get_db)
):
    """
    Get all model versions
    """
    models = db.query(MLModel).order_by(MLModel.created_at.desc()).all()
    
    return [{
        "model_version": m.model_version,
        "model_type": m.model_type,
        "training_samples": m.training_samples,
        "is_active": m.is_active,
        "trained_at": m.trained_at,
        "deployed_at": m.deployed_at
    } for m in models]


@router.post("/activate/{model_version}")
async def activate_model(
    model_version: str,
    db: Session = Depends(get_db),
    _auth: TokenData = Depends(require_jwt),
):
    """
    Activate a specific model version
    """
    # Deactivate all models
    db.query(MLModel).update({MLModel.is_active: False})
    
    # Activate the specified model
    model = db.query(MLModel).filter(
        MLModel.model_version == model_version
    ).first()
    
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model version {model_version} not found"
        )
    
    model.is_active = True
    model.deployed_at = datetime.now()
    db.commit()
    
    # Reload the model in the service
    anomaly_service._load_latest_model()
    
    logger.info(f"Activated model version: {model_version}")
    
    return {
        "status": "success",
        "message": f"Model {model_version} activated",
        "model_version": model_version
    }


@router.post("/re-score")
async def re_score_events(
    limit: int = 500,
    db: Session = Depends(get_db),
    _auth: TokenData = Depends(require_jwt),
):
    """
    Re-evaluate the last N events using the current model to clear false positives
    """
    logger.info(f"Starting historical re-score of last {limit} events")
    
    result = anomaly_service.re_score_past_events(db=db, limit=limit)
    
    if result["status"] == "error":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["message"]
        )
    
    return result
