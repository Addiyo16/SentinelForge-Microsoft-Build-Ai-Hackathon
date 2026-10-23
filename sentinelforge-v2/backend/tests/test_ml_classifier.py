"""
Unit tests for Machine Learning Security Finding Classifier (Component B).
Tests feature extraction, calibrated prediction, priority tiers, and evaluation metrics.
"""

import pytest
from app.ml.features import extract_features, FindingFeatures
from app.ml.classifier import FindingClassifier, score_finding


class TestMLClassifier:
    @pytest.fixture
    def classifier(self):
        return FindingClassifier()

    def test_feature_extraction_vector_shape(self):
        finding = {
            "severity": "critical",
            "confidence": 0.95,
            "evidence": "pickle.loads(payload)",
            "line": 10,
        }
        feat = extract_features(
            finding=finding,
            code_context="import pickle\npayload = data",
            cyclomatic_complexity=3,
            loop_depth=0,
            language="python",
        )
        vec = feat.to_vector()
        assert len(vec) == len(FindingFeatures.feature_names())
        assert feat.is_dangerous_api == 1
        assert feat.rule_severity_score == 1.0

    def test_sanitization_detection_in_features(self):
        finding = {
            "severity": "high",
            "confidence": 0.90,
            "evidence": "os.system(shlex.quote(cmd))",
            "line": 15,
        }
        feat = extract_features(
            finding=finding,
            code_context="import os, shlex\nif is_valid(cmd):\n    os.system(shlex.quote(cmd))",
            language="python",
        )
        assert feat.has_sanitization == 1

    def test_predict_critical_vulnerability(self, classifier):
        finding = {
            "pattern": "os.system(",
            "severity": "critical",
            "confidence": 0.98,
            "evidence": "os.system(user_input)",
            "line": 7,
        }
        pred = classifier.predict(finding=finding, language="python")
        assert pred.is_valid is True
        assert pred.probability >= 0.70
        assert pred.priority_tier in ("CRITICAL_RISK", "HIGH_RISK")
        assert "dangerous API" in pred.rationale

    def test_predict_benign_or_low_risk(self, classifier):
        finding = {
            "severity": "low",
            "confidence": 0.30,
            "evidence": "def calculate_sum(a, b): return a + b",
            "line": 2,
        }
        pred = classifier.predict(
            finding=finding,
            code_context="def is_valid(x): return isinstance(x, int)",
            language="python",
        )
        assert pred.priority_tier in ("LOW_OR_BENIGN", "MEDIUM_RISK")

    def test_model_evaluation_metrics_validity(self, classifier):
        metrics = classifier.evaluate()
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1_score" in metrics
        assert metrics["f1_score"] >= 0.50
        assert metrics["sample_count"] > 0

    def test_dataset_loader_and_schema(self):
        from app.ml.dataset import SecurityDatasetLoader
        samples = SecurityDatasetLoader.get_curated_benchmark()
        assert len(samples) >= 10
        first = samples[0]
        assert hasattr(first, "sample_id")
        assert hasattr(first, "repository_id")
        assert hasattr(first, "split_group")
        assert first.label in (0, 1)

    def test_repository_grouped_split_prevents_leakage(self):
        from app.ml.dataset import SecurityDatasetLoader
        from app.ml.preprocessing import repository_grouped_split, clean_and_deduplicate
        samples = SecurityDatasetLoader.get_curated_benchmark()
        cleaned = clean_and_deduplicate(samples)

        train, val, test = repository_grouped_split(cleaned, seed=42)
        train_groups = {s.split_group for s in train}
        val_groups = {s.split_group for s in val}
        test_groups = {s.split_group for s in test}

        # Verify zero cross-split group leakage
        assert len(train_groups.intersection(val_groups)) == 0
        assert len(train_groups.intersection(test_groups)) == 0
        assert len(val_groups.intersection(test_groups)) == 0

    def test_classification_metrics_and_ablation_study(self):
        from app.ml.evaluate import compute_classification_metrics, run_ablation_study
        y_true = [1, 1, 0, 0]
        y_pred = [1, 0, 0, 0]
        y_prob = [0.9, 0.4, 0.2, 0.1]
        metrics = compute_classification_metrics(y_true, y_pred, y_prob)

        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 0.5
        assert "pr_auc" in metrics
        assert "false_positive_rate" in metrics
        assert metrics["false_positive_rate"] == 0.0

        # Ablation study
        eval_samples = [
            {"label": 1, "has_pattern": True, "has_sanitization": False, "patch_verified": True},
            {"label": 0, "has_pattern": True, "has_sanitization": True, "patch_verified": True},
        ]
        ablation = run_ablation_study(eval_samples)
        assert "1_deterministic_rules_only" in ablation
        assert "2_deterministic_plus_ml" in ablation
        assert "3_deterministic_plus_ml_plus_rag" in ablation
        assert "4_full_pipeline_with_verification" in ablation
        # ML model eliminates false positive from sanitized pattern
        assert ablation["2_deterministic_plus_ml"]["false_positive_rate"] < ablation["1_deterministic_rules_only"]["false_positive_rate"]

    def test_model_registry_compatibility(self):
        from app.ml.model_registry import ModelRegistry
        registry = ModelRegistry()
        meta = registry.load_metadata()
        assert meta is not None
        assert meta.version == "2.1.0"
        assert len(meta.feature_schema) == 11
        assert registry.validate_schema_compatibility(FindingFeatures.feature_names()) is True

