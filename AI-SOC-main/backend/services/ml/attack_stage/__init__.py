"""
Attack Stage Prediction Module (Model 2)

Complete redesign with:
- Full 14 MITRE ATT&CK tactic coverage
- No 'unknown' stages (enhanced enrichment + queue system)
- Critical stage auto-escalation (stages 11-14)
- LSTM-based dynamic timing prediction
- Proper final stage handling
"""

from .stage_predictor import AttackStagePredictor
from .stage_identifier import AttackStageIdentifier

__all__ = ['AttackStagePredictor', 'AttackStageIdentifier']
