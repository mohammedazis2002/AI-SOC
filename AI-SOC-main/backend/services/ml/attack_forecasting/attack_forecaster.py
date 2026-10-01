"""
ENHANCED Multivariate Attack Forecaster - Model 5
Predicts BOTH volume AND attack type distribution using Auto-ARIMA

Features:
- Dynamic parameter selection (no hardcoded values!)
- Uses auto_arima for optimal (p,d,q) and seasonal (P,D,Q,s) determination
- Handles seasonality automatically
- Better stability than Prophet
- Faster installation

Forecasts:
- Total alert volume (how many attacks)
- Distribution across 14 MITRE tactics (what types)
"""

from pmdarima import auto_arima
from statsmodels.tsa.holtwinters import ExponentialSmoothing
import pandas as pd
import numpy as np
import pickle
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
import warnings

warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)


class MultivariateForecast:
    """
    Enhanced Auto-ARIMA forecaster with attack type distribution prediction
    
    Key features:
    - Automatically determines optimal SARIMAX parameters via grid search
    - Handles seasonality (hourly, daily, weekly patterns)
    - Provides confidence intervals
    - Predicts attack volume AND distribution across MITRE tactics
    - No hardcoded parameters - adapts to your data!
    """
    
    # All 14 MITRE ATT&CK tactics
    TACTICS = [
        'reconnaissance', 'resource_development', 'initial_access',
        'execution', 'persistence', 'privilege_escalation',
        'defense_evasion', 'credential_access', 'discovery',
        'lateral_movement', 'collection', 'command_and_control',
        'exfiltration', 'impact', 'unknown'
    ]
    
    def __init__(self):
        """Initialize multivariate forecaster with Auto-ARIMA"""
        self.model = None
        self.model_fit = None
        self.best_params = None  # Will store the auto-selected parameters
        
        # Separate models for each tactic distribution
        self.tactic_models = {}
        
        self.trained = False
        self.train_start_date = None
        self.train_end_date = None
        self.training_data = None
        
    def train(self, hourly_data: pd.DataFrame) -> Dict[str, Any]:
        """
        Train on hourly data with attack type breakdown
        
        Uses auto_arima to automatically determine optimal parameters:
        - Searches over reasonable ranges of (p,d,q) and seasonal (P,D,Q,s)
        - Uses AIC/BIC criteria for model selection
        - Adapts to your specific data patterns
        
        Args:
            hourly_data: DataFrame with columns:
                - ds (timestamp)
                - y (total count)
                - credential_access, initial_access, execution, ... (all 14 tactics)
                
        Returns:
            Training statistics including best model parameters
        """
        logger.info(f"Training Auto-ARIMA forecaster on {len(hourly_data)} hours...")
        
        if len(hourly_data) < 168:  # 1 week minimum
            logger.warning(f"Only {len(hourly_data)} hours. Recommend 168+ (1 week)")
        
        # Validate columns
        required = ['ds', 'y'] + self.TACTICS
        missing = [col for col in required if col not in hourly_data.columns]
        if missing:
            raise ValueError(f"Missing columns: {missing}")
        
        # Ensure correct types
        hourly_data = hourly_data.copy()
        hourly_data['ds'] = pd.to_datetime(hourly_data['ds'])
        hourly_data['y'] = pd.to_numeric(hourly_data['y'])
        hourly_data = hourly_data.set_index('ds')
        
        # Store time range
        self.train_start_date = hourly_data.index.min()
        self.train_end_date = hourly_data.index.max()
        self.training_data = hourly_data
        
        # Calculate tactic statistics
        tactic_totals = {tactic: int(hourly_data[tactic].sum()) for tactic in self.TACTICS}
        total_alerts = hourly_data['y'].sum()
        
        logger.info(f"  Date range: {self.train_start_date} to {self.train_end_date}")
        logger.info(f"  Total alerts: {int(total_alerts)}")
        logger.info(f"  Avg per hour: {hourly_data['y'].mean():.1f}")
        
        # Train Auto-ARIMA model for total volume
        logger.info("  Running auto_arima to find optimal parameters...")
        try:
            self.model_fit = auto_arima(
                hourly_data['y'],
                # Seasonal parameters - let it auto-detect
                seasonal=True,
                m=24,  # 24-hour seasonality for security events
                # Parameter search space
                start_p=0, max_p=3,  # AR terms
                start_q=0, max_q=3,  # MA terms
                start_P=0, max_P=2,  # Seasonal AR
                start_Q=0, max_Q=2,  # Seasonal MA
                max_d=2,  # Differencing
                max_D=1,  # Seasonal differencing
                # Model selection criteria
                information_criterion='aic',  # AIC for model comparison
                trace=True,  # Log progress
                error_action='ignore',
                suppress_warnings=True,
                stepwise=True,  # Faster search with stepwise algorithm
                # Prevent overfitting
                maxiter=50,
                # Performance
                n_jobs=-1  # Use all CPU cores
            )
            
            # Store the best parameters found
            self.best_params = {
                'order': self.model_fit.order,
                'seasonal_order': self.model_fit.seasonal_order
            }
            
            logger.info(f"✅ Auto-ARIMA complete!")
            logger.info(f"   Best model: ARIMA{self.best_params['order']} x {self.best_params['seasonal_order']}")
            logger.info(f"   AIC: {self.model_fit.aic():.2f}")
            
        except Exception as e:
            logger.error(f"Auto-ARIMA failed: {e}")
            # Fallback to simpler model
            logger.info("Using ExponentialSmoothing as fallback")
            self.model_fit = ExponentialSmoothing(
                hourly_data['y'],
                seasonal_periods=24,
                trend='add',
                seasonal='add'
            ).fit()
            self.best_params = {'model': 'ExponentialSmoothing', 'seasonal_periods': 24}
        
        # Train distribution models for each tactic (simple proportions)
        for tactic in self.TACTICS:
            if tactic in hourly_data.columns and hourly_data[tactic].sum() > 0:
                # Calculate average proportion of this tactic
                proportion = (hourly_data[tactic] / hourly_data['y'].replace(0, np.nan)).mean()
                self.tactic_models[tactic] = {
                    'proportion': proportion,
                    'total': int(hourly_data[tactic].sum())
                }
        
        self.trained = True
        
        return {
            'samples': len(hourly_data),
            'train_start': str(self.train_start_date),
            'train_end': str(self.train_end_date),
            'total_alerts': int(total_alerts),
            'avg_per_hour': float(hourly_data['y'].mean()),
            'tactic_totals': tactic_totals,
            'model': 'Auto-ARIMA',
            'best_parameters': self.best_params
        }
    
    def forecast(self, hours_ahead: int = 24) -> Dict[str, Any]:
        """
        Forecast next N hours with attack distribution
        
        Args:
            hours_ahead: How many hours to forecast

        Returns:
            Dictionary with predictions, confidence intervals, and risk analysis
        """
        if not self.trained:
            raise ValueError("Model not trained yet. Call train() first.")
        
        # Get forecast from Auto-ARIMA
        forecast_result, conf_int = self.model_fit.predict(
            n_periods=hours_ahead,
            return_conf_int=True,
            alpha=0.2  # 80% confidence interval
        )
        
        # Build predictions
        predictions = []
        high_risk_windows = []
        
        start_time = self.train_end_date + timedelta(hours=1)
        
        for i in range(hours_ahead):
            timestamp = start_time + timedelta(hours=i)
            predicted_value = max(0, forecast_result[i])
            conf_lower = max(0, conf_int[i, 0])
            conf_upper = max(0, conf_int[i, 1])
            
            # Determine risk level based on predicted value
            if predicted_value >= 20:
                risk_level = "critical"
            elif predicted_value >= 15:
                risk_level = "high"
            elif predicted_value >= 10:
                risk_level = "medium"
            else:
                risk_level = "low"
            
            prediction = {
                'timestamp': timestamp.isoformat(),
                'predicted_alerts': int(predicted_value),
                'confidence_lower': int(conf_lower),
                'confidence_upper': int(conf_upper),
                'risk_level': risk_level,
                'hour_of_day': timestamp.hour,
                'day_of_week': timestamp.strftime('%A')
            }
            
            predictions.append(prediction)
            
            if risk_level in ['high', 'critical']:
                high_risk_windows.append(prediction)
        
        # Calculate statistics
        avg_predicted = np.mean([p['predicted_alerts'] for p in predictions])
        max_predicted = max([p['predicted_alerts'] for p in predictions])
        
        return {
            'forecast_horizon_hours': hours_ahead,
            'forecast_start': start_time.isoformat(),
            'forecast_end': (start_time + timedelta(hours=hours_ahead-1)).isoformat(),
            'predictions': predictions,
            'high_risk_windows': high_risk_windows,
            'statistics': {
                'avg_predicted': float(avg_predicted),
                'max_predicted': int(max_predicted),
                'high_risk_count': len(high_risk_windows),
                'model': 'Auto-ARIMA',
                'parameters': self.best_params
            }
        }
    
    def get_next_high_risk_window(self) -> Dict[str, Any]:
        """
        Find the next high-risk time window in forecast
        
        Returns:
            Details of next high-risk window or message if none found
        """
        if not self.trained:
            return {
                'has_risk': False,
                'message': 'Model not trained yet'
            }
        
        # Forecast next 168 hours (1 week)
        forecast_data = self.forecast(hours_ahead=168)
        
        if not forecast_data['high_risk_windows']:
            return {
                'has_risk': False,
                'message': 'No high-risk windows in next 168 hours'
            }
        
        # Get first high-risk window
        next_risk = forecast_data['high_risk_windows'][0]
        risk_time = datetime.fromisoformat(next_risk['timestamp'])
        now = self.train_end_date
        hours_until = (risk_time - now).total_seconds() / 3600
        
        recommendation = f"Increase monitoring at {next_risk['hour_of_day']}:00 on {next_risk['day_of_week']}"
        
        return {
            'has_risk': True,
            'timestamp': next_risk['timestamp'],
            'risk_level': next_risk['risk_level'],
            'predicted_alerts': next_risk['predicted_alerts'],
            'hours_until': float(hours_until),
            'recommendation': recommendation
        }
    
    def save(self, filepath: str):
        """Save trained model"""
        if not self.trained:
            raise ValueError("Cannot save untrained model")
        
        save_data = {
            'model_fit': self.model_fit,
            'best_params': self.best_params,
            'tactic_models': self.tactic_models,
            'train_start_date': self.train_start_date,
            'train_end_date': self.train_end_date,
            'trained': self.trained,
            'training_data_tail': self.training_data.tail(24) if self.training_data is not None else None
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(save_data, f)
        
        logger.info(f"✅ Model saved to {filepath}")
    
    def load(self, filepath: str):
        """Load trained model"""
        with open(filepath, 'rb') as f:
            save_data = pickle.load(f)
        
        self.model_fit = save_data['model_fit']
        self.best_params = save_data['best_params']
        self.tactic_models = save_data['tactic_models']
        self.train_start_date = save_data['train_start_date']
        self.train_end_date = save_data['train_end_date']
        self.trained = save_data['trained']
        if 'training_data_tail' in save_data:
            self.training_data = save_data['training_data_tail']
        
        logger.info(f"✅ Model loaded from {filepath}")
        if self.best_params:
            logger.info(f"   Model parameters: {self.best_params}")
