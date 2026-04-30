"""
Behavioral ML Analyzer - Real-time UEBA anomaly detection.

Hybrid scoring:
- IsolationForest model score (0-10)
- Profile/context deviation score (0-10)
- Low-and-slow accumulator (0-10 contribution cap)
"""
import logging
import math
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from .feature_extractor import EventFeatureExtractor

logger = logging.getLogger(__name__)


def _clamp_0_10(v: float) -> float:
    return max(0.0, min(10.0, float(v)))


def _normalize_anomaly_raw(raw_score: float, worker_cfg) -> float:
    """Normalize model raw score to unified anomaly scale [0,10]."""
    method = str(getattr(worker_cfg, "ML_ANOMALY_NORM_METHOD", "percentile") or "percentile").lower()
    if method == "minmax":
        lo = float(getattr(worker_cfg, "ML_ANOMALY_MIN", -1.0))
        hi = float(getattr(worker_cfg, "ML_ANOMALY_MAX", 1.0))
    else:
        lo = float(getattr(worker_cfg, "ML_ANOMALY_P5", -0.6))
        hi = float(getattr(worker_cfg, "ML_ANOMALY_P95", 0.6))
    if hi <= lo:
        lo, hi = -1.0, 1.0
    x = min(max(float(raw_score), lo), hi)
    return _clamp_0_10((x - lo) / (hi - lo) * 10.0)


class BehavioralMLAnalyzer:
    def __init__(self, model_path: Optional[Path] = None):
        if model_path is None:
            model_path = Path(__file__).parent.parent / "worker" / "ml_models" / "ueba_iso_forest.pkl"
        self.model_path = Path(model_path)
        self.model = None
        self.scaler = None
        self.feature_names: List[str] = []
        self.feature_extractor = EventFeatureExtractor()
        self.is_loaded = False
        self._accumulator: Dict[str, Dict[str, float]] = {}
        # Baseline per-user (persist across worker restarts).
        # Stored as lightweight JSON (atomic replace) under worker/logs/ for easy inspection.
        try:
            base = Path(__file__).parent.parent / "worker" / "logs" / "ueba"
            base.mkdir(parents=True, exist_ok=True)
        except Exception:
            base = Path(__file__).parent
        self._profile_path = Path(os.getenv("UEBA_PROFILE_PATH", str(base / "ueba_user_baselines.json")))
        self._profiles: Dict[str, Dict[str, Any]] = {}
        self._profile_dirty = 0
        self._profile_last_save_ts = 0.0
        self._profile_save_every = max(1, int(os.getenv("UEBA_PROFILE_SAVE_EVERY", "25")))
        self._profile_save_min_sec = max(0.2, float(os.getenv("UEBA_PROFILE_SAVE_MIN_SEC", "2.0")))
        self._profile_decay_hours = max(1.0, float(os.getenv("UEBA_PROFILE_DECAY_HOURS", "168")))  # 7d default
        self._profile_min_events = max(10, int(os.getenv("UEBA_PROFILE_MIN_EVENTS", "35")))
        self._load_profiles()
        if not self.model_path.exists():
            logger.warning(f"UEBA model not found at {self.model_path}. Anomaly detection disabled.")

    def _load_profiles(self) -> None:
        try:
            if not self._profile_path.exists():
                return
            raw = self._profile_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, dict) and isinstance(data.get("profiles"), dict):
                self._profiles = data["profiles"]
        except Exception as e:
            logger.warning(f"UEBA baseline load failed: {e}")

    def _save_profiles(self, force: bool = False) -> None:
        try:
            now = datetime.now().timestamp()
            if not force:
                if self._profile_dirty <= 0:
                    return
                if self._profile_dirty < self._profile_save_every and (now - self._profile_last_save_ts) < self._profile_save_min_sec:
                    return
            payload = {
                "version": 1,
                "saved_ts": now,
                "profiles": self._profiles,
            }
            tmp = self._profile_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self._profile_path)
            self._profile_dirty = 0
            self._profile_last_save_ts = now
        except Exception as e:
            logger.debug(f"UEBA baseline save failed: {e}")

    def load_model(self) -> bool:
        try:
            model_data = joblib.load(self.model_path)
            if isinstance(model_data, dict):
                self.model = model_data.get("model")
                self.scaler = model_data.get("scaler")
                self.feature_names = model_data.get("feature_names", []) or []
            else:
                self.model = model_data
                self.scaler = None
                self.feature_names = []
            self.is_loaded = self.model is not None
            if self.is_loaded:
                logger.info(f"UEBA model loaded from {self.model_path}")
            return self.is_loaded
        except Exception as e:
            logger.error(f"Failed to load UEBA model: {e}")
            self.is_loaded = False
            return False

    def _parse_ts(self, event: Dict[str, Any]) -> datetime:
        ts = event.get("ts") or event.get("timestamp")
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(float(ts))
        s = str(ts or "").replace("Z", "+00:00")
        if s:
            try:
                return datetime.fromisoformat(s)
            except Exception:
                pass
        return datetime.now()

    def _extract_user(self, event: Dict[str, Any]) -> str:
        ctx = event.get("context", {}) or {}
        actor = event.get("actor", {}) or {}
        return str(
            ctx.get("user")
            or actor.get("user")
            or event.get("user")
            or "unknown"
        ).strip().lower()

    def _model_input_features(self, raw_features: np.ndarray) -> np.ndarray:
        """
        Backward compatibility for models trained on older feature sets.
        - If model has saved feature_names, map by name.
        - Else fallback to raw features.
        """
        if not self.feature_names:
            return raw_features
        names_now = self.feature_extractor.get_feature_names()
        idx_map = {name: i for i, name in enumerate(names_now)}
        out = np.zeros((len(self.feature_names),), dtype=np.float32)
        for i, fname in enumerate(self.feature_names):
            j = idx_map.get(fname)
            if j is not None and j < len(raw_features):
                out[i] = raw_features[j]
        return out

    def _event_signals(self, event: Dict[str, Any]) -> Dict[str, float]:
        ctx = event.get("context", {}) or {}
        operation = event.get("operation", {}) or {}
        obj = event.get("object", {}) or {}
        clipboard = event.get("clipboard", {}) or {}
        network = event.get("network", {}) or {}
        e_type = str(event.get("type") or event.get("event_type") or "").lower()
        op_type = str(operation.get("op_type") or "").lower()
        dst = str(obj.get("dst_path") or event.get("dst_path") or "").lower()
        app = str(ctx.get("fg_app") or ctx.get("process_name") or operation.get("tool") or "").lower()
        domain = str(clipboard.get("dest_domain") or network.get("dest_domain") or ctx.get("dest_domain") or "").lower()
        file_path = str(obj.get("path") or "").lower()

        is_clipboard = 1.0 if "clipboard" in e_type or "paste" in op_type else 0.0
        is_external = 1.0 if any(x in dst for x in ("usb", "removable", "onedrive", "dropbox")) or any(
            x in domain for x in ("drive.google", "dropbox", "onedrive", "wetransfer", "mega", "telegram")
        ) else 0.0
        is_archive = 1.0 if any(x in file_path for x in (".zip", ".rar", ".7z")) else 0.0
        is_rename_like = 1.0 if any(x in e_type for x in ("rename", "modified")) and any(
            x in file_path for x in (".tmp", ".dat", ".bin")
        ) else 0.0
        app_risky = 1.0 if any(x in app for x in ("chrome", "edge", "discord", "telegram", "zalo", "chatgpt")) else 0.0
        file_size = float(event.get("size") or obj.get("size") or obj.get("size_bytes") or 0.0)
        
        is_file_op = 1.0 if any(x in e_type for x in ("file_", "upload", "usb_copy")) else 0.0
        
        clip_content = clipboard.get("content", "")
        clip_len = clipboard.get("content_len", len(str(clip_content)))
        actual_size = file_size if file_size > 0 else clip_len
        is_small_fragment = 1.0 if (is_clipboard > 0.0 or is_file_op > 0.0) and 0 < actual_size < 512 else 0.0

        return {
            "is_clipboard": is_clipboard,
            "is_external": is_external,
            "is_archive": is_archive,
            "is_rename_like": is_rename_like,
            "app_risky": app_risky,
            "file_size_mb": file_size / (1024.0 * 1024.0),
            "is_small_fragment": is_small_fragment,
        }

    def _get_user_profile(self, user: str) -> Dict[str, Any]:
        p = self._profiles.get(user)
        if not isinstance(p, dict):
            p = {
                "n": 0,
                "last_ts": 0.0,
                # Exponential moving averages (EMA) of key habits.
                "ema_off_hours": 0.0,
                "ema_external": 0.0,
                "ema_clipboard": 0.0,
                "ema_risky_app": 0.0,
                # Optional hour histogram (0-23) for explainability.
                "hour_hist": [0] * 24,
            }
            self._profiles[user] = p
        return p

    def _ema_alpha(self, elapsed_hours: float) -> float:
        # Convert elapsed time to EMA alpha using a decay horizon.
        # alpha ~ 1-exp(-dt/T). Clamp for stability.
        T = float(self._profile_decay_hours)
        if T <= 0:
            return 0.2
        a = 1.0 - math.exp(-max(0.0, elapsed_hours) / T)
        return max(0.005, min(0.35, a))

    def _update_user_profile(self, user: str, ts: datetime, signal: Dict[str, float]) -> Dict[str, Any]:
        p = self._get_user_profile(user)
        last_ts = float(p.get("last_ts") or 0.0)
        now_ts = float(ts.timestamp())
        elapsed_h = 0.0 if last_ts <= 0 else max(0.0, (now_ts - last_ts) / 3600.0)
        alpha = self._ema_alpha(elapsed_h)

        is_off = 1.0 if (ts.hour < 8 or ts.hour >= 18) else 0.0
        p["ema_off_hours"] = (1 - alpha) * float(p.get("ema_off_hours", 0.0)) + alpha * is_off
        p["ema_external"] = (1 - alpha) * float(p.get("ema_external", 0.0)) + alpha * float(signal.get("is_external", 0.0))
        p["ema_clipboard"] = (1 - alpha) * float(p.get("ema_clipboard", 0.0)) + alpha * float(signal.get("is_clipboard", 0.0))
        p["ema_risky_app"] = (1 - alpha) * float(p.get("ema_risky_app", 0.0)) + alpha * float(signal.get("app_risky", 0.0))

        try:
            hh = p.get("hour_hist")
            if isinstance(hh, list) and len(hh) == 24:
                hh[ts.hour] = int(hh[ts.hour] or 0) + 1
        except Exception:
            pass

        p["n"] = int(p.get("n") or 0) + 1
        p["last_ts"] = now_ts
        self._profile_dirty += 1
        self._save_profiles(force=False)
        return p

    def _baseline_drift_score(self, ts: datetime, signal: Dict[str, float], profile: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score how far the current event deviates from the user's long-term baseline.
        Output is [0..10] and a list of reasons for defendability.
        """
        n = int(profile.get("n") or 0)
        if n < self._profile_min_events:
            return {"score": 0.0, "reasons": ["baseline_warmup"], "n": n}

        off_b = float(profile.get("ema_off_hours") or 0.0)
        ext_b = float(profile.get("ema_external") or 0.0)
        clip_b = float(profile.get("ema_clipboard") or 0.0)
        risky_b = float(profile.get("ema_risky_app") or 0.0)

        is_off = 1.0 if (ts.hour < 8 or ts.hour >= 18) else 0.0
        is_ext = float(signal.get("is_external") or 0.0)
        is_clip = float(signal.get("is_clipboard") or 0.0)
        is_risky = float(signal.get("app_risky") or 0.0)

        score = 0.0
        reasons: List[str] = []

        # Off-hours: only strong when user rarely works off-hours.
        if is_off > 0 and off_b < 0.10:
            score += 2.4
            reasons.append(f"off_hours_vs_baseline(p={off_b:.2f})")
        elif is_off > 0 and off_b < 0.25:
            score += 1.2
            reasons.append(f"off_hours_elevated(p={off_b:.2f})")

        # External channel (USB/cloud/messaging domain signals): strong when baseline is low.
        if is_ext > 0 and ext_b < 0.05:
            score += 3.2
            reasons.append(f"external_channel_first_time(p={ext_b:.2f})")
        elif is_ext > 0 and ext_b < 0.15:
            score += 1.6
            reasons.append(f"external_channel_rare(p={ext_b:.2f})")

        # Clipboard paste: spike is handled by short-term profile; here we detect baseline drift.
        if is_clip > 0 and clip_b < 0.05:
            score += 1.2
            reasons.append(f"clipboard_unusual(p={clip_b:.2f})")

        # Risky app usage: when baseline risky-app is low.
        if is_risky > 0 and risky_b < 0.10:
            score += 1.3
            reasons.append(f"risky_app_unusual(p={risky_b:.2f})")

        # Sequence synergy: off-hours + external + risky app is strong.
        if is_off > 0 and is_ext > 0 and is_risky > 0:
            score += 1.4
            reasons.append("sequence_offhours_external_riskyapp")
        elif is_off > 0 and is_ext > 0:
            score += 0.8
            reasons.append("sequence_offhours_external")

        return {"score": _clamp_0_10(score), "reasons": reasons, "n": n}

    def _profile_deviation(self, event: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
        now = self._parse_ts(event)
        user = self._extract_user(event)
        user_hist = [e for e in history if self._extract_user(e) == user]
        recent_10m = []
        recent_1h = []
        for e in user_hist:
            dt = self._parse_ts(e)
            delta = (now - dt).total_seconds()
            if 0 <= delta <= 600:
                recent_10m.append(e)
            if 0 <= delta <= 3600:
                recent_1h.append(e)

        off_hours_hist = 0
        for e in user_hist[-200:]:
            h = self._parse_ts(e).hour
            if h < 8 or h >= 18:
                off_hours_hist += 1
        off_hours_ratio = (off_hours_hist / max(1, len(user_hist[-200:]))) if user_hist else 0.0
        is_off_hours = 1.0 if (now.hour < 8 or now.hour >= 18) else 0.0

        signal = self._event_signals(event)
        clipboard_count = sum(
            1 for e in recent_10m if self._event_signals(e)["is_clipboard"] > 0
        )
        ext_count_1h = sum(
            1 for e in recent_1h if self._event_signals(e)["is_external"] > 0
        )
        ext_baseline = sum(
            1 for e in user_hist[-200:] if self._event_signals(e)["is_external"] > 0
        ) / max(1, min(200, len(user_hist)))

        deviation = 0.0
        reasons: List[str] = []

        # Case 1 guard: off-hours alone should only raise slightly.
        if is_off_hours and off_hours_ratio < 0.08:
            deviation += 1.0
            reasons.append("off_hours_deviation")

        if clipboard_count >= 15:
            deviation += 1.2
            reasons.append("clipboard_spike_10m")
        elif clipboard_count >= 8:
            deviation += 0.6
            reasons.append("clipboard_elevated_10m")
            
        # Fragmented Exfiltration Check
        small_clip_ext_1h = sum(
            1 for e in recent_1h 
            if self._event_signals(e).get("is_small_fragment", 0.0) > 0 
            and (self._event_signals(e)["is_external"] > 0 or self._event_signals(e)["app_risky"] > 0)
        )

        if small_clip_ext_1h >= 4:
            deviation += 2.5
            reasons.append(f"fragmented_exfiltration_1h({small_clip_ext_1h})")
        elif small_clip_ext_1h >= 2:
            deviation += 1.0
            reasons.append(f"suspicious_fragments_1h({small_clip_ext_1h})")

        if ext_count_1h >= 6:
            deviation += 2.2
            reasons.append("external_channel_spike_1h")
        elif ext_count_1h >= 3:
            deviation += 1.0
            reasons.append("external_channel_elevated_1h")

        if ext_baseline < 0.05 and signal["is_external"] > 0:
            deviation += 1.2
            reasons.append("channel_baseline_drift")

        if signal["app_risky"] > 0 and signal["is_clipboard"] > 0 and small_clip_ext_1h < 2:
            deviation += 1.0
            reasons.append("risky_app_clipboard_sequence")

        if signal["is_archive"] > 0 or signal["is_rename_like"] > 0:
            deviation += 0.9
            reasons.append("transformation_signal")

        return {
            "score": _clamp_0_10(deviation),
            "reasons": reasons,
            "off_hours_ratio": round(off_hours_ratio, 3),
            "clipboard_10m": clipboard_count,
            "external_1h": ext_count_1h,
        }

    def _update_accumulator(self, user: str, ts: datetime, profile_score: float, signal: Dict[str, float]) -> float:
        state = self._accumulator.get(user, {"value": 0.0, "ts": ts.timestamp()})
        elapsed_h = max(0.0, (ts.timestamp() - float(state["ts"])) / 3600.0)
        decay = math.exp(-elapsed_h / 6.0)  # ~6h half-life-like decay
        value = float(state["value"]) * decay

        incremental = 0.0
        if signal["is_external"] > 0:
            incremental += 0.45
        if signal["is_archive"] > 0 or signal["is_rename_like"] > 0:
            incremental += 0.35
            
        # Fragmented Exfiltration accelerates accumulation significantly
        if signal.get("is_small_fragment", 0.0) > 0 and (signal["is_external"] > 0 or signal["app_risky"] > 0):
            incremental += 1.2
            
        if profile_score >= 2.0:
            incremental += min(0.6, profile_score / 10.0)

        value = min(6.0, value + incremental)  # Cap tại 6.0 để cho phép fragmented exfil tích lũy đủ để trigger alert (previous cap: 3.0)

        self._accumulator[user] = {"value": value, "ts": ts.timestamp()}
        return value

    def predict(self, event: Dict[str, Any], event_history: Optional[list] = None) -> Dict[str, Any]:
        if self.model_path.exists() and not self.is_loaded:
            self.load_model()
        if not self.is_loaded or self.model is None:
            return {"anomaly_score": 0.0, "is_anomaly": False, "features": None, "error": "Model not loaded"}

        try:
            history = event_history or []
            if history:
                self.feature_extractor.event_history = history

            raw_features = self.feature_extractor.extract(event)
            model_features = self._model_input_features(raw_features)
            model_features_2d = model_features.reshape(1, -1)
            if self.scaler is not None:
                model_features_2d = self.scaler.transform(model_features_2d)

            raw_score = float(self.model.decision_function(model_features_2d)[0])
            try:
                from worker.config import WorkerConfig
            except Exception:
                WorkerConfig = None

            if WorkerConfig is not None:
                model_score = _normalize_anomaly_raw(raw_score, WorkerConfig)
                threshold = float(getattr(WorkerConfig, "ML_ANOMALY_THRESHOLD", 7.0))
                boost_factor = float(getattr(WorkerConfig, "ML_ANOMALY_RISK_BOOST_FACTOR", 1.0))
            else:
                model_score = _clamp_0_10((raw_score + 1.0) * 5.0)
                threshold = 7.0
                boost_factor = 1.0

            profile = self._profile_deviation(event, history)
            user = self._extract_user(event)
            ts = self._parse_ts(event)
            signal = self._event_signals(event)
            user_profile = self._update_user_profile(user, ts, signal)
            baseline = self._baseline_drift_score(ts, signal, user_profile)
            accum = self._update_accumulator(user, ts, float(profile["score"]), signal)

            anomaly_score = _clamp_0_10(
                model_score * 0.65
                + float(profile["score"]) * 0.25
                + float(baseline["score"]) * 0.10
                + accum * max(0.0, min(1.0, boost_factor))
            )
            is_anomaly = anomaly_score >= threshold

            return {
                "anomaly_score": float(anomaly_score),
                "is_anomaly": bool(is_anomaly),
                "features": raw_features,
                "raw_score": raw_score,
                "model_score": round(model_score, 3),
                "profile_score": round(float(profile["score"]), 3),
                "baseline_score": round(float(baseline["score"]), 3),
                "slow_burn_score": round(accum, 3),
                "profile_reasons": profile["reasons"],
                "baseline_reasons": baseline["reasons"],
                "baseline_n": int(baseline.get("n") or 0),
            }
        except Exception as e:
            logger.error(f"Error predicting anomaly: {e}")
            return {"anomaly_score": 0.0, "is_anomaly": False, "features": None, "error": str(e)}

    def is_available(self) -> bool:
        if self.model_path.exists() and not self.is_loaded:
            self.load_model()
        return self.is_loaded and self.model is not None
