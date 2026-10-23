"""Neural/ML refinement head (Phase 4).

Loaded once via FusionModel.get(); predict() returns P(category) for all 9 categories.
If artifacts are missing, get() returns None and the engine runs symbolic-only, so the
service never depends on the model being present.

The model (logistic regression over symbolic features ⊕ TF-IDF char n-grams) is trained
only on data/synthetic/train.jsonl. It never executes submitted code.
"""
from pathlib import Path

ARTIFACTS = Path(__file__).parent / "artifacts"


class FusionModel:
    _instance = None
    _loaded = False

    @classmethod
    def get(cls):
        if not cls._loaded:
            cls._loaded = True
            try:
                cls._instance = cls._load()
            except Exception:
                cls._instance = None
        return cls._instance

    @classmethod
    def _load(cls):
        head = ARTIFACTS / "head.joblib"
        if not head.exists():
            return None
        import joblib
        bundle = joblib.load(head)
        return cls(bundle)

    def __init__(self, bundle):
        import numpy as np
        self._np = np
        self.clf = bundle["clf"]
        self.scaler = bundle["scaler"]
        self.tfidf = bundle["tfidf"]
        self.feature_names = bundle["feature_names"]
        self.categories = bundle["categories"]
        self.version = bundle.get("version", "?")

    def predict(self, code, language, sym_features):
        from scipy.sparse import csr_matrix, hstack
        from engine.features import vectorize
        vec = self._np.array([vectorize(sym_features, self.feature_names)], dtype="float32")
        sym_s = self.scaler.transform(vec)
        tf = self.tfidf.transform([code])
        X = hstack([csr_matrix(sym_s), tf]).tocsr()
        if hasattr(self.clf, "predict_proba"):
            probs = self.clf.predict_proba(X)[0]
        else:
            d = self.clf.decision_function(X)[0]
            probs = 1.0 / (1.0 + self._np.exp(-d))
        return {c: float(p) for c, p in zip(self.categories, probs)}
