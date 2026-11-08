# Minimal typing stubs for the subset of scikit-learn used by ironmesh_anomaly.ml.
from typing import Any, Self

import numpy as np
from numpy.typing import ArrayLike

class IsolationForest:
    offset_: float
    n_features_in_: int
    max_samples_: int
    estimators_: list[Any]
    estimators_features_: list[Any]
    def __init__(
        self,
        *,
        n_estimators: int = ...,
        max_samples: int | float | str = ...,
        contamination: float | str = ...,
        max_features: int | float = ...,
        bootstrap: bool = ...,
        n_jobs: int | None = ...,
        random_state: int | None = ...,
        verbose: int = ...,
        warm_start: bool = ...,
    ) -> None: ...
    def fit(self, X: ArrayLike, y: Any = ..., sample_weight: ArrayLike | None = ...) -> Self: ...
    def predict(self, X: ArrayLike) -> np.ndarray[Any, np.dtype[np.int64]]: ...
    def decision_function(self, X: ArrayLike) -> np.ndarray[Any, np.dtype[np.float64]]: ...
    def score_samples(self, X: ArrayLike) -> np.ndarray[Any, np.dtype[np.float64]]: ...
