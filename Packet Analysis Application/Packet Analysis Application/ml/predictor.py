"""
ML Predictor — Load model đã train và predict gói tin real-time.

Sử dụng:
    predictor = MLPredictor("ml/")
    label, confidence = predictor.predict(features_array)
"""

import os
import json
import logging
import numpy as np
import joblib

logger = logging.getLogger(__name__)


class MLPredictor:
    """
    Load model Random Forest đã train và predict trên features mới.

    Attributes:
        model: RandomForestClassifier đã train
        scaler: StandardScaler đã fit
        label_encoder: LabelEncoder để decode nhãn
        metadata: dict chứa thông tin model
    """

    def __init__(self, model_dir: str = "ml"):
        """
        Load model từ thư mục.

        Args:
            model_dir: đường dẫn đến thư mục chứa model.joblib,
                       scaler.joblib, label_encoder.joblib, metadata.json
        """
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.metadata = None
        self.is_loaded = False

        self._load(model_dir)

    def _load(self, model_dir: str):
        """Load tất cả file cần thiết."""
        model_path = os.path.join(model_dir, "model.joblib")
        scaler_path = os.path.join(model_dir, "scaler.joblib")
        le_path = os.path.join(model_dir, "label_encoder.joblib")
        meta_path = os.path.join(model_dir, "metadata.json")

        # Kiểm tra file tồn tại
        for path, name in [
            (model_path, "model"),
            (scaler_path, "scaler"),
            (le_path, "label_encoder"),
            (meta_path, "metadata"),
        ]:
            if not os.path.exists(path):
                logger.warning(f"ML: Không tìm thấy {name}: {path}")
                print(f"⚠ ML: Không tìm thấy {path}")
                return

        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.label_encoder = joblib.load(le_path)

            with open(meta_path, 'r', encoding='utf-8') as f:
                self.metadata = json.load(f)

            self.is_loaded = True
            acc = self.metadata.get("accuracy", 0) * 100
            n_labels = len(self.metadata.get("labels", []))
            print(f"✓ ML Model loaded: accuracy={acc:.1f}%, {n_labels} labels")
            logger.info(f"ML Model loaded from {model_dir}")

        except Exception as e:
            logger.error(f"ML: Lỗi load model: {e}", exc_info=True)
            print(f"⚠ ML: Lỗi load model: {e}")

    def predict(self, features: np.ndarray) -> tuple[str, float]:
        """
        Predict nhãn cho 1 gói tin.

        Args:
            features: numpy array shape (11,) từ FeatureExtractor

        Returns:
            (label, confidence) — ví dụ: ("DDoS", 0.95)
            Nếu model chưa load: ("N/A", 0.0)
        """
        if not self.is_loaded:
            return "N/A", 0.0

        try:
            # Reshape thành (1, n_features) cho sklearn
            X = features.reshape(1, -1)

            # Chuẩn hóa
            X_scaled = self.scaler.transform(X)

            # Predict nhãn
            y_pred = self.model.predict(X_scaled)[0]
            label = self.label_encoder.inverse_transform([y_pred])[0]

            # Predict xác suất (confidence)
            proba = self.model.predict_proba(X_scaled)[0]
            confidence = float(np.max(proba))

            return label, confidence

        except Exception as e:
            logger.error(f"ML predict error: {e}")
            return "Error", 0.0

    def predict_batch(self, features_list: list[np.ndarray]) -> list[tuple[str, float]]:
        """
        Predict batch — nhanh hơn predict từng cái khi load PCAP.

        Args:
            features_list: list các numpy array shape (11,)

        Returns:
            list of (label, confidence)
        """
        if not self.is_loaded or not features_list:
            return [("N/A", 0.0)] * len(features_list)

        try:
            X = np.vstack(features_list)
            X_scaled = self.scaler.transform(X)

            y_preds = self.model.predict(X_scaled)
            labels = self.label_encoder.inverse_transform(y_preds)

            probas = self.model.predict_proba(X_scaled)
            confidences = np.max(probas, axis=1)

            return list(zip(labels.tolist(), confidences.tolist()))

        except Exception as e:
            logger.error(f"ML batch predict error: {e}")
            return [("Error", 0.0)] * len(features_list)

    def get_labels(self) -> list[str]:
        """Trả về danh sách nhãn model có thể phân loại."""
        if self.metadata:
            return self.metadata.get("labels", [])
        return []

    def get_accuracy(self) -> float:
        """Trả về accuracy khi train."""
        if self.metadata:
            return self.metadata.get("accuracy", 0.0)
        return 0.0