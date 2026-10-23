"""
SentinelForge — Model Versioning, Artifact Management & Schema Compatibility (Section 3.8)
Handles saving, loading, version verification, and metadata tracking for trained models.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
import joblib

from app.ml.features import FindingFeatures


MODEL_REGISTRY_VERSION = "2.1.0"


@dataclass
class ModelMetadata:
    version: str
    model_type: str
    feature_schema: list[str]
    training_samples: int
    optimal_threshold: float
    metrics: dict[str, Any]
    trained_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "model_type": self.model_type,
            "feature_schema": self.feature_schema,
            "training_samples": self.training_samples,
            "optimal_threshold": self.optimal_threshold,
            "metrics": self.metrics,
            "trained_at": self.trained_at,
        }


class ModelRegistry:
    """
    Manages persistence and schema compatibility of model artifacts.
    """

    MODEL_FILENAME = "finding_model.joblib"
    METADATA_FILENAME = "model_metadata.json"

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(self.base_dir, self.MODEL_FILENAME)
        self.meta_path = os.path.join(self.base_dir, self.METADATA_FILENAME)

    def save_model(self, model: Any, metadata: ModelMetadata):
        """Persist model artifact and metadata."""
        joblib.dump(model, self.model_path)
        with open(self.meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata.to_dict(), f, indent=2)

    def load_model(self) -> Optional[Any]:
        """Load model artifact if present."""
        if os.path.exists(self.model_path):
            try:
                return joblib.load(self.model_path)
            except Exception:
                return None
        return None

    def load_metadata(self) -> Optional[ModelMetadata]:
        """Load model metadata if present."""
        if os.path.exists(self.meta_path):
            try:
                with open(self.meta_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return ModelMetadata(**data)
            except Exception:
                return None
        return None

    def validate_schema_compatibility(self, current_features: list[str]) -> bool:
        """Verify that current feature extraction matches the model's schema."""
        meta = self.load_metadata()
        if not meta:
            return True
        return meta.feature_schema == current_features
