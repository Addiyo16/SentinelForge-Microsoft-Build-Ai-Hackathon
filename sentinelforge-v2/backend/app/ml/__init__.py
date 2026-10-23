"""
SentinelForge — Machine Learning Security Package (Section 3)
Provides dataset management, preprocessing, feature extraction, multi-model training,
ablation evaluation, and model artifact registry.
"""

from app.ml.dataset import CodeSample, SecurityDatasetLoader
from app.ml.preprocessing import normalize_code_snippet, clean_and_deduplicate, repository_grouped_split
from app.ml.features import FindingFeatures, extract_features
from app.ml.evaluate import compute_classification_metrics, run_ablation_study
from app.ml.model_registry import ModelRegistry, ModelMetadata, MODEL_REGISTRY_VERSION
from app.ml.train import train_and_select_best_model
from app.ml.classifier import FindingClassifier, MLPrediction, score_finding

__all__ = [
    "CodeSample",
    "SecurityDatasetLoader",
    "normalize_code_snippet",
    "clean_and_deduplicate",
    "repository_grouped_split",
    "FindingFeatures",
    "extract_features",
    "compute_classification_metrics",
    "run_ablation_study",
    "ModelRegistry",
    "ModelMetadata",
    "MODEL_REGISTRY_VERSION",
    "train_and_select_best_model",
    "FindingClassifier",
    "MLPrediction",
    "score_finding",
]
