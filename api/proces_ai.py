"""
Alias module for api/process_ai.py to support both spelling variants.
"""
from api.process_ai import app, predict_model_rf, predict_model_svm, process_ai_endpoint

__all__ = ["app", "predict_model_rf", "predict_model_svm", "process_ai_endpoint"]
