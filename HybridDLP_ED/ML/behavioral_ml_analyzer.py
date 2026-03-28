"""
Behavioral ML Analyzer - Real-time UEBA anomaly detection
Tích hợp với L3 Detection Engine
"""
import numpy as np
from typing import Dict, Any, Optional
from pathlib import Path
import joblib
import logging

# Setup logging
logger = logging.getLogger(__name__)

from .feature_extractor import EventFeatureExtractor


def _normalize_anomaly_raw(raw_score: float, worker_cfg) -> float:
    method = getattr(worker_cfg, "ML_ANOMALY_NORM_METHOD", "percentile")
    method = str(method or "percentile").lower()
    if method == "minmax":
        lo = float(getattr(worker_cfg, "ML_ANOMALY_MIN", -1.0))
        hi = float(getattr(worker_cfg, "ML_ANOMALY_MAX", 1.0))
    else:
        lo = float(getattr(worker_cfg, "ML_ANOMALY_P5", -0.6))
        hi = float(getattr(worker_cfg, "ML_ANOMALY_P95", 0.6))
    if hi <= lo:
        lo, hi = -1.0, 1.0
    x = min(max(float(raw_score), lo), hi)
    return max(0.0, min(100.0, (x - lo) / (hi - lo) * 100.0))


class BehavioralMLAnalyzer:
    """
    Load trained Isolation Forest model và predict anomaly scores
    Sử dụng trong L3 Detection Engine để phát hiện hành vi bất thường
    """
    
    def __init__(self, model_path: Optional[Path] = None):
        """
        Initialize ML analyzer
        
        Args:
            model_path: Path to trained Isolation Forest model (.pkl file)
        """
        if model_path is None:
            # Default path: worker/ml_models/ueba_iso_forest.pkl
            model_path = Path(__file__).parent.parent / "worker" / "ml_models" / "ueba_iso_forest.pkl"
        
        self.model_path = Path(model_path)
        self.model = None
        self.scaler = None
        self.feature_names = []
        self.feature_extractor = EventFeatureExtractor()
        self.is_loaded = False
        # Lazy load: không gọi load_model() trong __init__ (Sensor/Worker khởi động nhẹ — Noteupdate)
        if not self.model_path.exists():
            logger.warning(f"UEBA model not found at {self.model_path}. Anomaly detection disabled.")
    
    def load_model(self) -> bool:
        """Load Isolation Forest model from disk"""
        try:
            model_data = joblib.load(self.model_path)
            
            # Handle both old format (direct model) and new format (dict with model + scaler)
            if isinstance(model_data, dict):
                self.model = model_data['model']
                self.scaler = model_data.get('scaler')
                self.feature_names = model_data.get('feature_names', [])
            else:
                # Old format: direct model
                self.model = model_data
                self.scaler = None
                self.feature_names = []
            
            self.is_loaded = True
            logger.info(f"UEBA model loaded from {self.model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load UEBA model: {e}")
            self.is_loaded = False
            return False
    
    def predict(self, event: Dict[str, Any], event_history: Optional[list] = None) -> Dict[str, Any]:
        """
        Predict anomaly score for an event
        
        Args:
            event: Event dictionary
            event_history: List of recent events for frequency calculations
        
        Returns:
            Dictionary with:
            - anomaly_score: float [0, 100] (higher = more anomalous)
            - is_anomaly: bool
            - features: numpy array
        """
        if self.model_path.exists() and not self.is_loaded:
            self.load_model()
        if not self.is_loaded or self.model is None:
            return {
                'anomaly_score': 0.0,
                'is_anomaly': False,
                'features': None,
                'error': 'Model not loaded'
            }
        
        try:
            # Update feature extractor with event history
            if event_history:
                self.feature_extractor.event_history = event_history
            
            # Extract features
            features = self.feature_extractor.extract(event)
            features_2d = features.reshape(1, -1)  # Shape: (1, n_features)
            
            # Scale features if scaler is available
            if self.scaler is not None:
                features_2d = self.scaler.transform(features_2d)
            
            # Predict anomaly score
            # Isolation Forest returns: -1 (anomaly) to 1 (normal)
            raw_score = self.model.decision_function(features_2d)[0]
            
            try:
                from worker.config import WorkerConfig
            except Exception:
                WorkerConfig = None

            if WorkerConfig is not None:
                base_anomaly_score = _normalize_anomaly_raw(raw_score, WorkerConfig)
                boost_factor = float(getattr(WorkerConfig, "ML_ANOMALY_RISK_BOOST_FACTOR", 0.0))
                threshold = float(getattr(WorkerConfig, "ML_ANOMALY_THRESHOLD", 70.0))
            else:
                base_anomaly_score = max(0.0, min(100.0, (1 - raw_score) / 2 * 100))
                boost_factor = 0.0
                threshold = 75.0
            
            # Apply risk boost for high-risk cases (ChatGPT, USB, etc.)
            risk_boost = self._calculate_risk_boost(features_2d[0]) * max(0.0, min(1.0, boost_factor))
            anomaly_score = min(100.0, base_anomaly_score + risk_boost)
            
            # Threshold: score > threshold is considered anomaly (configurable)
            # Default threshold: 75 (có thể config trong config.py)
            is_anomaly = anomaly_score > threshold
            
            return {
                'anomaly_score': float(anomaly_score),
                'is_anomaly': is_anomaly,
                'features': features,
                'raw_score': float(raw_score)
            }
        
        except Exception as e:
            logger.error(f"Error predicting anomaly: {e}")
            return {
                'anomaly_score': 0.0,
                'is_anomaly': False,
                'features': None,
                'error': str(e)
            }
    
    def _calculate_risk_boost(self, features: np.ndarray) -> float:
        """
        Calculate risk boost for high-risk cases (ChatGPT, USB, etc.)
        
        Args:
            features: Feature array of shape (13,)
        
        Returns:
            Risk boost score [0, 30] to add to base anomaly score
        """
        boost = 0.0
        
        # High-risk destination categories
        dest_category_idx = 10  # dest_app_category
        dest_category = features[dest_category_idx]
        
        # USB/External (category = 1.0 after normalization)
        if dest_category >= 0.95:  # USB
            boost += 15.0  # High boost for USB
        
        # Chat App (category = 0.5 after normalization)
        elif dest_category >= 0.45 and dest_category < 0.55:  # Chat (ChatGPT, etc.)
            boost += 12.0  # High boost for ChatGPT
        
        # Cloud Sync (category = 0.75 after normalization)
        elif dest_category >= 0.7 and dest_category < 0.8:  # Cloud
            boost += 8.0
        
        # Browser (category = 0.25 after normalization)
        elif dest_category >= 0.2 and dest_category < 0.3:  # Browser
            boost += 5.0
        
        # Off-hours activity
        is_off_hours_idx = 0
        if features[is_off_hours_idx] > 0.5:
            boost += 5.0
        
        # High entropy (encrypted/sensitive data)
        entropy_idx = 7
        if features[entropy_idx] > 0.8:
            boost += 8.0
        
        # USB transfers
        usb_bytes_idx = 5
        if features[usb_bytes_idx] > 0.01:  # Any USB transfer
            boost += 10.0
        
        # Bulk clipboard paste activity
        clipboard_pastes_idx = 4
        if features[clipboard_pastes_idx] > 0.15:  # More than 15 pastes
            boost += 5.0
        
        return min(30.0, boost)  # Cap boost at 30 points
    
    def is_available(self) -> bool:
        """Check if model is loaded and available"""
        if self.model_path.exists() and not self.is_loaded:
            self.load_model()
        return self.is_loaded and self.model is not None
