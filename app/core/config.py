"""
Configuration settings for the AI-SOC application
"""
from pydantic_settings import BaseSettings
from typing import Optional
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings"""
    
    # API Settings
    api_title: str = "AI-SOC Anomaly Detection API"
    api_version: str = "1.0.0"
    api_description: str = "SIEM/SOC Anomaly Detection with Compliance Mapping"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_reload: bool = True
    
    # Database Settings
    database_url: str = "sqlite:///./aisoc.db"
    
    # Security Settings
    secret_key: str = "change-this-secret-key-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480  # 8 hours

    # Auth — user passwords (override via env vars in production)
    admin_password: str = "aisoc-admin-2024"
    analyst_password: str = "aisoc-analyst-2024"

    # API key for internal services (log agent)
    api_key: str = "aisoc-internal-api-key-change-me"
    
    # ML Model Settings
    model_path: str = "./models"
    min_training_samples: int = 100
    anomaly_threshold: float = -0.5
    contamination_rate: float = 0.05
    
    # Logging Settings
    log_level: str = "INFO"
    log_file: str = "./logs/aisoc.log"
    
    # Redis Settings
    redis_url: str = "redis://localhost:6379/0"
    
    # Monitoring
    enable_metrics: bool = True
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": False,
        "protected_namespaces": (),  # suppress model_ prefix warnings
        "extra": "ignore",           # silently ignore unknown env vars (e.g. DB_PASSWORD)
    }


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
