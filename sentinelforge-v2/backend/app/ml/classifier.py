"""
SentinelForge — Supervised Finding Validation & Prioritization Model (Component B)
Trained classifier that estimates whether a candidate security finding is a genuine vulnerability
and calculates calibrated priority ranking scores.
"""

import os
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

from app.ml.features import FindingFeatures, extract_features


@dataclass
class MLPrediction:
    is_valid: bool
    probability: float          # Calibrated probability (0.0 to 1.0)
    priority_score: int         # 0 to 100 normalized priority
    priority_tier: str          # CRITICAL_RISK | HIGH_RISK | MEDIUM_RISK | LOW_OR_BENIGN
    rationale: str              # Explanation of model decision


class FindingClassifier:
    """
    Supervised model for candidate finding validation and prioritization.
    """

    MODEL_FILENAME = "finding_model.joblib"

    def __init__(self):
        self.model = None
        self.is_trained = False
        self.threshold = 0.40
        self._init_or_load()

    def _init_or_load(self):
        from app.ml.model_registry import ModelRegistry
        self.registry = ModelRegistry()
        self.model = self.registry.load_model()
        meta = self.registry.load_metadata()
        if self.model is not None:
            self.is_trained = True
            if meta and hasattr(meta, "optimal_threshold"):
                self.threshold = meta.optimal_threshold
            return

        from app.ml.train import train_and_select_best_model
        res = train_and_select_best_model()
        self.model = self.registry.load_model()
        self.threshold = res.get("optimal_threshold", 0.40)
        self.is_trained = True

    def train_baseline(self):
        """
        Train a calibrated ensemble model on curated security weakness samples
        and negative controls (sanitized or benign patterns).
        """
        X_train, y_train = self._generate_training_dataset()

        base_rf = RandomForestClassifier(
            n_estimators=60,
            max_depth=6,
            random_state=42,
            class_weight="balanced"
        )
        # Calibrate probabilities using cross-validation
        calibrated = CalibratedClassifierCV(estimator=base_rf, cv=3)
        calibrated.fit(X_train, y_train)

        self.model = calibrated
        self.is_trained = True

        # Persist model artifact
        try:
            model_dir = os.path.dirname(os.path.abspath(__file__))
            joblib.dump(self.model, os.path.join(model_dir, self.MODEL_FILENAME))
        except Exception:
            pass

    def predict(
        self,
        finding: dict,
        code_context: str = "",
        cyclomatic_complexity: int = 1,
        loop_depth: int = 0,
        language: str = "python",
    ) -> MLPrediction:
        """
        Score a single candidate finding and return calibrated validity prediction.
        """
        if not self.is_trained or self.model is None:
            self.train_baseline()

        # Source validation: Declarative files cannot execute algorithmic loop constructs (CWE-400)
        s_file = str(finding.get("source_file") or "").lower()
        r_id = str(finding.get("rule_id") or "")
        cwe = str(finding.get("cwe_id") or "").upper()
        desc = str(finding.get("description") or "").lower()
        is_decl = (
            language.lower() in ("yaml", "yml", "json", "toml", "xml", "markdown", "text", "config")
            or s_file.endswith((".yml", ".yaml", ".json", ".toml", ".xml", ".ini", ".cfg", ".md", ".txt"))
        )
        if is_decl and (r_id == "AST-PERF-001" or cwe == "CWE-400" or "nested loop" in desc):
            return MLPrediction(
                is_valid=False,
                probability=0.0,
                priority_score=0,
                priority_tier="LOW_OR_BENIGN",
                rationale="Validated against source: Declarative configuration files do not execute algorithmic loop constructs (CWE-400 non-applicable).",
            )

        feat = extract_features(
            finding=finding,
            code_context=code_context,
            cyclomatic_complexity=cyclomatic_complexity,
            loop_depth=loop_depth,
            language=language,
        )
        vec = np.array([feat.to_vector()])

        proba = float(self.model.predict_proba(vec)[0][1])
        is_valid = bool(proba >= getattr(self, "threshold", 0.40))
        priority_score = int(round(proba * 100))

        if priority_score >= 80:
            tier = "CRITICAL_RISK"
        elif priority_score >= 55:
            tier = "HIGH_RISK"
        elif priority_score >= 35:
            tier = "MEDIUM_RISK"
        else:
            tier = "LOW_OR_BENIGN"

        # Construct decision rationale
        factors = []
        if feat.is_dangerous_api:
            factors.append("presence of recognized dangerous API call")
        if feat.has_sanitization:
            factors.append("mitigated by nearby input validation/sanitization")
        if feat.has_auth_context:
            factors.append("involves security-sensitive credentials/tokens")
        if feat.loop_depth >= 2:
            factors.append(f"nested loop iteration depth ({feat.loop_depth})")

        factor_str = ", ".join(factors) if factors else "baseline heuristic metrics"
        rationale = f"ML model estimated {priority_score}% validity probability based on {factor_str}."

        return MLPrediction(
            is_valid=is_valid,
            probability=round(proba, 4),
            priority_score=priority_score,
            priority_tier=tier,
            rationale=rationale,
        )

    def evaluate(self) -> dict[str, Any]:
        """
        Evaluate model performance metrics against curated benchmark validation split.
        Returns precision, recall, F1-score, and confusion matrix.
        """
        meta = self.registry.load_metadata()
        if meta and meta.metrics and "test_evaluation" in meta.metrics:
            test_m = meta.metrics["test_evaluation"]
            return {
                "model": meta.model_type,
                "version": meta.version,
                "precision": test_m.get("precision", 0.0),
                "recall": test_m.get("recall", 0.0),
                "f1_score": test_m.get("f1_score", 0.0),
                "pr_auc": test_m.get("pr_auc", 0.0),
                "confusion_matrix": test_m.get("confusion_matrix", {}),
                "sample_count": test_m.get("sample_count", 0),
            }

        X_val, y_val = self._generate_validation_dataset()
        probs = self.model.predict_proba(X_val)[:, 1]
        preds = (probs >= getattr(self, "threshold", 0.40)).astype(int)

        p = float(precision_score(y_val, preds, zero_division=0))
        r = float(recall_score(y_val, preds, zero_division=0))
        f1 = float(f1_score(y_val, preds, zero_division=0))
        cm = confusion_matrix(y_val, preds).tolist()

        return {
            "model": "TrainedClassifier",
            "precision": round(p, 4),
            "recall": round(r, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm,
            "sample_count": len(y_val),
        }

    def _generate_training_dataset(self) -> tuple[np.ndarray, np.ndarray]:
        """
        Curate representative dataset covering:
          - Positive: Insecure Deserialization, OS Command Injection, Buffer Overflow, SQLi, Secrets.
          - Negative: Sanitized calls, unit tests, benign math operations, safe wrappers.
        """
        samples = []
        labels = []

        # Synthetic samples: [rule_sev, scanner_conf, is_dang, has_sanit, has_auth, cc, loop_d, line, len, entropy, lang]
        # True Positives (Genuinely vulnerable)
        positives = [
            [1.0, 0.98, 1, 0, 0, 3, 0, 12, 35, 3.8, 0],   # pickle.loads unsanitized
            [1.0, 0.99, 1, 0, 0, 2, 0, 8, 42, 4.1, 0],    # os.system(payload)
            [1.0, 0.95, 1, 0, 0, 5, 0, 15, 30, 3.9, 3],   # strcpy stack buffer overflow
            [0.75, 0.92, 1, 0, 0, 2, 0, 22, 40, 4.2, 1],  # dangerouslySetInnerHTML
            [1.0, 0.96, 1, 0, 1, 1, 0, 5, 45, 4.0, 2],    # readObject RCE
            [0.75, 0.90, 0, 0, 1, 1, 0, 2, 28, 4.3, 0],   # exposed hardcoded secret
            [0.75, 0.85, 0, 0, 0, 4, 2, 18, 55, 3.5, 0],  # O(N^2) nested loop exhaustion
            [1.0, 0.97, 1, 0, 0, 3, 0, 10, 32, 4.0, 0],   # eval(raw_input)
            [0.75, 0.92, 0, 0, 0, 1, 0, 7, 25, 3.7, 5],   # chmod 777 in YAML
            [1.0, 0.95, 1, 0, 1, 2, 0, 14, 50, 4.2, 3],   # gets() with admin buffer
        ] * 8

        # True Negatives (Benign / Sanitized false positives)
        negatives = [
            [0.5, 0.40, 0, 1, 0, 1, 0, 20, 25, 3.0, 0],   # benign function call
            [1.0, 0.90, 1, 1, 0, 4, 0, 30, 60, 4.0, 0],   # os.system with shlex.quote sanitization
            [0.75, 0.80, 0, 1, 0, 2, 0, 15, 30, 3.2, 1],  # sanitized innerHTML
            [0.25, 0.30, 0, 0, 0, 1, 0, 5, 18, 2.9, 0],   # simple add(a, b)
            [0.75, 0.85, 0, 0, 1, 1, 0, 8, 22, 3.5, 0],   # os.environ.get("TOKEN") - not hardcoded
            [0.5, 0.50, 0, 0, 0, 2, 1, 12, 40, 3.3, 0],   # single loop (not nested)
            [1.0, 0.85, 1, 1, 0, 3, 0, 25, 45, 3.8, 3],   # strncpy with explicit bound check
            [0.5, 0.45, 0, 1, 0, 2, 0, 9, 32, 3.1, 2],    # parameterized SQL query
            [0.25, 0.20, 0, 0, 0, 1, 0, 1, 15, 2.8, 5],   # harmless config comment
            [0.5, 0.55, 0, 1, 0, 3, 0, 14, 38, 3.4, 4],   # sanitized exec.Command with slice
        ] * 8

        X = np.array(positives + negatives)
        y = np.array([1] * len(positives) + [0] * len(negatives))
        return X, y

    def _generate_validation_dataset(self) -> tuple[np.ndarray, np.ndarray]:
        """Independent validation set with varied parameters."""
        pos = [
            [1.0, 0.95, 1, 0, 0, 3, 0, 9, 38, 4.0, 0],
            [1.0, 0.98, 1, 0, 0, 2, 0, 14, 44, 4.1, 0],
            [0.75, 0.90, 0, 0, 1, 1, 0, 4, 30, 4.4, 0],
            [0.75, 0.85, 0, 0, 0, 5, 2, 22, 58, 3.6, 0],
            [1.0, 0.96, 1, 0, 0, 4, 0, 11, 35, 3.9, 3],
        ] * 4
        neg = [
            [0.5, 0.35, 0, 1, 0, 1, 0, 18, 22, 2.9, 0],
            [1.0, 0.88, 1, 1, 0, 3, 0, 32, 50, 3.9, 0],
            [0.25, 0.25, 0, 0, 0, 1, 0, 3, 14, 2.7, 0],
            [0.5, 0.50, 0, 0, 0, 2, 1, 10, 35, 3.2, 0],
            [0.5, 0.40, 0, 1, 0, 2, 0, 8, 28, 3.0, 2],
        ] * 4
        X = np.array(pos + neg)
        y = np.array([1] * len(pos) + [0] * len(neg))
        return X, y


# Global Singleton Classifier
_finding_classifier = FindingClassifier()


def score_finding(
    finding: dict,
    code_context: str = "",
    cyclomatic_complexity: int = 1,
    loop_depth: int = 0,
    language: str = "python",
) -> MLPrediction:
    """Helper function to score a finding using the singleton FindingClassifier."""
    return _finding_classifier.predict(
        finding=finding,
        code_context=code_context,
        cyclomatic_complexity=cyclomatic_complexity,
        loop_depth=loop_depth,
        language=language,
    )
