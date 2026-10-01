"""
Attack Forecaster Validation Script
===================================
Loads an attack_forecaster.pkl and evaluates predictions on the holdout (last 20%)
of the historical 1-hour feature dataframe.

Run from project root:
  python backend/scripts/train_models/validation/validate_forecaster_performance.py
"""

import math
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from statsmodels.graphics.tsaplots import plot_acf, plot_pacf


def _error_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    diff = y_pred - y_true
    mae = np.mean(np.abs(diff))
    mse = np.mean(diff ** 2)
    rmse = math.sqrt(mse)
    mape = np.mean(np.abs(diff / (y_true + 1e-9))) * 100
    return {
        "mae": float(mae),
        "mse": float(mse),
        "rmse": float(rmse),
        "mape": float(mape),
    }


def main():
    root_dir = Path(__file__).resolve().parents[4]
    models_dir = root_dir / "backend/models"
    features_dir = root_dir / "backend/data/features/v1"

    model_path = models_dir / "attack_forecaster.pkl"
    data_path = features_dir / "behavioral_features_1h.parquet"

    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")
    if not data_path.exists():
        raise FileNotFoundError(f"Data file not found: {data_path}")

    with open(model_path, "rb") as f:
        artifact = pickle.load(f)

    if artifact.get("model_fit") is None:
        print("Model is flat/insufficient-seasonality fallback (no fitted ExponentialSmoothing).")
        return

    model_fit = artifact["model_fit"]

    df = pd.read_parquet(data_path)
    df = df.sort_values("timestamp").reset_index(drop=True)

    y_all = df.groupby("timestamp")["total_alerts"].sum()
    split_idx = int(len(y_all) * 0.8)

    y_train = y_all.iloc[:split_idx]
    y_holdout = y_all.iloc[split_idx:]

    print(f"Total time windows: {len(y_all)}")
    print(f"Training windows:    {len(y_train)}")
    print(f"Holdout windows:     {len(y_holdout)}")

    plot_dir = root_dir / "backend" / "scripts" / "train_models" / "validation" / "plots"
    plot_acf_pacf(y_train, plot_dir)

    print("\n=== Hyperparameter tuning: ExponentialSmoothing grid search ===")
    best = tune_exponential_smoothing(y_train, y_holdout)
    print(f"Best params: {best['params']} with RMSE={best['rmse']:.3f}")

    # retrain with the best hyperparameters on the full series (train + holdout)
    if best["params"] is not None:
        print("\nRetraining best model on the full dataset...")
        from statsmodels.tsa.holtwinters import ExponentialSmoothing

        model_fit = ExponentialSmoothing(
            y_all,
            trend=best["params"]["trend"],
            seasonal=best["params"]["seasonal"],
            seasonal_periods=best["params"]["seasonal_periods"],
        ).fit(optimized=True)

    # Forecast holdout horizon from end of train set
    horizon = len(y_holdout)
    forecast = model_fit.forecast(horizon)

    if len(forecast) != horizon:
        raise ValueError("Forecast horizon mismatch with holdout length")

    y_pred = np.asarray(forecast, dtype=float)
    y_true = np.asarray(y_holdout, dtype=float)

    metrics = _error_metrics(y_true, y_pred)

    print("\n=== Forecast Performance (Holdout) ===")
    print(f"MAE : {metrics['mae']:.3f}")
    print(f"MSE : {metrics['mse']:.3f}")
    print(f"RMSE: {metrics['rmse']:.3f}")
    print(f"MAPE: {metrics['mape']:.2f}%")

    print("\n=== Holdout Comparison (first 10 rows) ===")
    df_report = pd.DataFrame({
        "timestamp": y_holdout.index,
        "y_true": y_true,
        "y_pred": y_pred,
        "error": y_pred - y_true,
        "abs_error": np.abs(y_pred - y_true),
    })
    print(df_report.head(10).to_string(index=False))


def plot_acf_pacf(series: pd.Series, out_dir: Path, lags: int = 48):
    out_dir.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(2, 1, figsize=(10, 8))
    plot_acf(series, lags=lags, ax=ax[0], zero=True)
    ax[0].set_title("ACF (Autocorrelation)")

    plot_pacf(series, lags=lags, ax=ax[1], method="ywm")
    ax[1].set_title("PACF (Partial Autocorrelation)")

    plt.tight_layout()
    save_path = out_dir / "attack_forecaster_acf_pacf.png"
    fig.savefig(save_path)
    plt.close(fig)
    print(f"ACF/PACF plot saved to {save_path}")


def tune_exponential_smoothing(y_train: pd.Series, y_holdout: pd.Series):
    from statsmodels.tsa.holtwinters import ExponentialSmoothing

    param_grid = [
        {"trend": "add", "seasonal": "add", "seasonal_periods": 24},
        {"trend": "add", "seasonal": "mul", "seasonal_periods": 24},
        {"trend": "mul", "seasonal": "add", "seasonal_periods": 24},
        {"trend": "mul", "seasonal": "mul", "seasonal_periods": 24},
        {"trend": None, "seasonal": None, "seasonal_periods": None},
    ]

    best = {"rmse": float("inf"), "params": None, "model_fit": None}

    for params in param_grid:
        try:
            model = ExponentialSmoothing(
                y_train,
                trend=params["trend"],
                seasonal=params["seasonal"],
                seasonal_periods=params["seasonal_periods"],
            )
            fit = model.fit(optimized=True)

            horizon = len(y_holdout)
            pred = fit.forecast(horizon)

            diff = np.asarray(pred, dtype=float) - np.asarray(y_holdout, dtype=float)
            rmse = math.sqrt(np.mean(diff ** 2))

            print(f"params={params} -> RMSE={rmse:.3f}")

            if rmse < best["rmse"]:
                best.update({"rmse": rmse, "params": params, "model_fit": fit})
        except Exception as exc:
            print(f"  Skipping params={params} due to error: {exc}")

    return best


if __name__ == "__main__":
    main()
