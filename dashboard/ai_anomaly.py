#!/usr/bin/env python3
"""
ULPF AI Threat Hunting & Anomaly Detection Engine
Track 3 (Phase 2): Unsupervised Machine Learning on Vectorized OCSF Telemetry
NTRO Problem Statement ID: 26156
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from typing import List



class ThreatAnomalyDetector:
    """
    Unsupervised Isolation Forest model trained directly on standardized OCSF Network Activity (Class 4001) vectors.
    """
    def __init__(self, contamination: float = 0.08, random_state: int = 42):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=120,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )
        self.is_fitted = False
        self.feature_columns = [
            "src_port_norm",
            "dst_port_norm",
            "is_privileged_dst",
            "is_blocked",
            "proto_code",
            "is_common_web"
        ]

    def _extract_features(self, df: pd.DataFrame) -> np.ndarray:
        """Transforms OCSF DataFrame into numeric feature matrix."""
        if df.empty:
            return np.empty((0, len(self.feature_columns)))

        # Feature 1 & 2: Normalized port distributions
        src_port = df["src_port"].fillna(0).astype(float) / 65535.0
        dst_port = df["dst_port"].fillna(0).astype(float) / 65535.0

        # Feature 3: Privileged destination ports (<1024 like 22, 53, 445)
        is_privileged = (df["dst_port"].fillna(0) < 1024).astype(float)

        # Feature 4: Disposition (Blocked/Dropped = 1.0, Allowed = 0.0)
        is_blocked = df["disposition"].apply(lambda x: 1.0 if str(x).lower() in ["blocked", "drop", "deny", "dropped"] else 0.0)

        # Feature 5: Protocol encoding (TCP=1.0, UDP=2.0, ICMP=3.0, Other=0.0)
        proto_map = {"tcp": 1.0, "udp": 2.0, "icmp": 3.0}
        proto_code = df["protocol_name"].astype(str).str.lower().map(proto_map).fillna(0.0)

        # Feature 6: Non-standard web traffic (Common web = 80, 443)
        is_common_web = df["dst_port"].isin([80, 443, 8080, 8443]).astype(float)

        feature_matrix = np.column_stack([
            src_port,
            dst_port,
            is_privileged,
            is_blocked,
            proto_code,
            is_common_web
        ])
        return feature_matrix

    def fit_predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Trains the Isolation Forest model on historical/live records and computes anomaly scores."""
        if len(df) < 10:
            df["anomaly_score"] = 0.15
            df["is_anomaly"] = False
            return df

        X = self._extract_features(df)
        self.model.fit(X)
        self.is_fitted = True

        # raw score: lower means more anomalous. Invert and scale to [0.0, 1.0]
        raw_scores = self.model.decision_function(X)
        # Normalize into 0.0 (benign) to 1.0 (highly anomalous)
        min_score = np.min(raw_scores)
        max_score = np.max(raw_scores)
        if max_score > min_score:
            anomaly_scores = 1.0 - (raw_scores - min_score) / (max_score - min_score)
        else:
            anomaly_scores = np.zeros(len(df))

        predictions = self.model.predict(X)  # -1 for anomaly, 1 for normal
        is_anomaly = predictions == -1

        df_result = df.copy()
        df_result["anomaly_score"] = np.round(anomaly_scores, 3)
        df_result["is_anomaly"] = is_anomaly
        return df_result

    def explain_anomaly(self, row: pd.Series) -> List[str]:
        """Provides heuristic explainability reasons for flagged anomalies."""
        reasons = []
        dst_port = row.get("dst_port", 0)
        disp = str(row.get("disposition", "")).lower()
        score = row.get("anomaly_score", 0.0)

        if dst_port in [22, 3389, 445, 23]:
            reasons.append(f"High-risk administrative port targeted (Port {dst_port})")
        if disp in ["blocked", "drop", "deny"]:
            reasons.append("Connection rejected by perimeter policy")
        if row.get("src_port", 0) < 1024 and row.get("src_port", 0) > 0:
            reasons.append("Privileged source port (non-standard client initiation)")
        if score > 0.80:
            reasons.append("Multi-dimensional feature vector divergence (>95th percentile outlier)")
        if not reasons:
            reasons.append("Unusual port entropy cluster identified by Isolation Forest")
        return reasons
