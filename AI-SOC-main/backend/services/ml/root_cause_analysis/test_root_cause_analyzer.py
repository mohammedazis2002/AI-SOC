"""
Test Suite for Root Cause Analyzer - Model 3
Tests 14-category multi-label classification
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from backend.services.ml.root_cause_analyzer import RootCauseAnalyzer
from backend.services.ml.root_cause_feature_extractor import RootCauseFeatureExtractor
import numpy as np


def test_categories():
    """Test that we have 14 categories"""
    analyzer = RootCauseAnalyzer()
    assert len(analyzer.CATEGORIES) == 14, f"Expected 14 categories, got {len(analyzer.CATEGORIES)}"
    
    # Verify new categories exist
    assert 'defense_evasion' in analyzer.CATEGORIES, "Missing defense_evasion category"
    assert 'api_security_gap' in analyzer.CATEGORIES, "Missing api_security_gap category"
    
    print("✅ Test 1: 14 categories verified")


def test_auto_suggest_labels():
    """Test semi-supervised auto-labeling"""
    analyzer = RootCauseAnalyzer()
    
    # Test alert 1: Brute force
    brute_force_alert = {
        'finding': {
            'types': ['T1110'],
            'desc': 'Multiple failed password attempts for admin account'
        },
        'user_has_mfa': False,
        'severity_id': 4
    }
    
    suggestions = analyzer.auto_suggest_labels(brute_force_alert)
   
    # Should suggest weak_credentials and lack_of_mfa
    assert suggestions['weak_credentials']['suggested'] == 1, "Should suggest weak_credentials"
    assert suggestions['lack_of_mfa']['suggested'] == 1, "Should suggest lack_of_mfa"
    assert suggestions['weak_credentials']['confidence'] >= 0.75, "Confidence too low"
    
    print("✅ Test 2: Auto-labeling for brute force works")
    
    # Test alert 2: CVE exploit
    cve_alert = {
        'finding': {
            'types': ['T1190'],
            'desc': 'Exploitation attempt using CVE-2023-12345'
        },
        'severity_id': 5
    }
    
    suggestions = analyzer.auto_suggest_labels(cve_alert)
    assert suggestions['unpatched_vulnerability']['suggested'] == 1, "Should suggest unpatched_vulnerability"
    
    print("✅ Test 3: Auto-labeling for CVE works")
    
    # Test alert 3: LOLBIN abuse
    lolbin_alert = {
        'finding': {
            'types': ['T1059'],
            'desc': 'Suspicious PowerShell execution detected'
        },
        'process': {'name': 'powershell.exe'}
    }
    
    suggestions = analyzer.auto_suggest_labels(lolbin_alert)
    assert suggestions['defense_evasion']['suggested'] == 1, "Should suggest defense_evasion"
    
    print("✅ Test 4: Auto-labeling for LOLBIN works")


def test_feature_extraction():
    """Test 30-feature extraction"""
    extractor = RootCauseFeatureExtractor()
    
    sample_alert = {
        'severity_id': 4,
        'finding': {
            'types': ['T1110', 'T1078'],
            'desc': 'Brute force attack succeeded'
        },
        'mitre_enrichment': {
            'dominant_tactic': 'credential_access'  # Underscore, not hyphen
        },
        'time': 1706000000000,  # Unix timestamp
        'process': {'name': 'cmd.exe'}
    }
    
    context = {
        'user_mfa_enabled': False,
        'user_role': 'admin',
        'asset_criticality': 0.9,
        'has_edr': True,
        'segmentation': 'basic'
    }
    
    features = extractor.extract(sample_alert, context)
    
    # Should return 30 features
    assert len(features) == 30, f"Expected 30 features, got {len(features)}"
    assert features.dtype == np.float32, "Features should be float32"
    
    # Check specific features
    assert features[0] == 4.0, "Severity should be 4.0"
    assert features[1] == 7.0, "credential-access should encode to 7.0"
    assert features[2] == 2.0, "Should have 2 techniques"
    assert features[10] == 0.0, "No MFA should be 0.0"
    assert features[11] == 1.0, "Admin should be 1.0"
    
    print("✅ Test 5: 30-feature extraction works")
    print(f"   Features shape: {features.shape}")
    print(f"   Sample features: {features[:5]}")


def test_model_training():
    """Test training on synthetic data"""
    analyzer = RootCauseAnalyzer()
    
    # Create synthetic training data
    np.random.seed(42)
    n_samples = 100
    n_features = 30
    n_categories = 14
    
    X = np.random.rand(n_samples, n_features).astype(np.float32)
    
    # Create multi-label targets (each sample can have 1-3 categories)
    y = np.zeros((n_samples, n_categories), dtype=np.int32)
    for i in range(n_samples):
        num_labels = np.random.randint(1, 4)  # 1-3 labels
        label_indices = np.random.choice(n_categories, size=num_labels, replace=False)
        y[i, label_indices] = 1
    
    # Train
    train_stats = analyzer.train(X, y, feature_names=RootCauseFeatureExtractor.FEATURE_NAMES)
    
    assert analyzer.trained, "Model should be trained"
    assert train_stats['num_samples'] == n_samples
    assert train_stats['num_features'] == n_features
    assert train_stats['num_categories'] == n_categories
    
    print("✅ Test 6: Model training works")
    print(f"   Samples: {train_stats['num_samples']}")
    print(f"   Avg labels/sample: {train_stats['avg_labels_per_sample']:.2f}")


def test_prediction():
    """Test prediction on sample data"""
    analyzer = RootCauseAnalyzer()
    
    # Train on synthetic data first
    np.random.seed(42)
    X_train = np.random.rand(100, 30).astype(np.float32)
    y_train = np.zeros((100, 14), dtype=np.int32)
    for i in range(100):
        y_train[i, np.random.randint(0, 14)] = 1
    
    analyzer.train(X_train, y_train)
    
    # Predict
    X_test = np.random.rand(5, 30).astype(np.float32)
    predictions = analyzer.predict(X_test, return_proba=True)
    
    assert predictions.shape == (5, 14), f"Wrong shape: {predictions.shape}"
    assert np.all((predictions >= 0) & (predictions <= 1)), "Probabilities should be 0-1"
    
    print("✅ Test 7: Prediction works")
    print(f"   Predictions shape: {predictions.shape}")


def test_analyze_alert():
    """Test complete alert analysis"""
    analyzer = RootCauseAnalyzer()
    extractor = RootCauseFeatureExtractor()
    
    # Train on synthetic data
    np.random.seed(42)
    X_train = np.random.rand(100, 30).astype(np.float32)
    y_train = np.zeros((100, 14), dtype=np.int32)  
    for i in range(100):
        # Make weak_credentials more common
        y_train[i, 0] = 1 if np.random.rand() > 0.3 else 0
        y_train[i, 3] = 1 if np.random.rand() > 0.5 else 0  # lack_of_mfa
    
    analyzer.train(X_train, y_train)
    
    # Create test alert
    test_alert = {
        'severity_id': 4,
        'finding': {
            'types': ['T1110'],
            'desc': 'Brute force attack detected'
        },
        'mitre_enrichment': {
            'dominant_tactic': 'credential_access'  # Underscore
        },
        'time': 1706000000000
    }
    
    features = extractor.extract(test_alert, {})
    
    analysis = analyzer.analyze_alert(features, alert_context={'mitre_tactic': 'credential_access'})
    
    assert 'num_root_causes' in analysis
    assert 'root_causes' in analysis
    assert 'remediation' in analysis
    assert len(analysis['remediation']) > 0, "Should have remediation steps"
    
    print("✅ Test 8: Complete alert analysis works")
    print(f"   Root causes found: {analysis['num_root_causes']}")
    if analysis['root_causes']:
        print(f"   Top cause: {analysis['root_causes'][0]['cause']} ({analysis['root_causes'][0]['confidence']:.2f})")


def test_temporal_priority():
    """Test temporal priority assignment"""
    analyzer = RootCauseAnalyzer()
    
    # Mock root causes
    root_causes = [
        {'cause': 'weak_credentials', 'confidence': 0.85, 'category_index': 0},
        {'cause': 'inadequate_segmentation', 'confidence': 0.75, 'category_index': 9},
        {'cause': 'insufficient_monitoring', 'confidence': 0.65, 'category_index': 4}
    ]
    
    # Context: early-stage attack (initial_access)
    context = {'mitre_tactic': 'initial_access'}  # Underscore
    
    prioritized = analyzer._add_temporal_priority(root_causes, context)
    
    # weak_credentials should be primary for initial access
    weak_cred = next(c for c in prioritized if c['cause'] == 'weak_credentials')
    assert weak_cred.get('priority') == 'primary', "weak_credentials should be primary for initial access"
    
    print("✅ Test 9: Temporal priority works")
    for cause in prioritized:
        print(f"   {cause['cause']}: {cause.get('priority', 'N/A')} (temporal_order: {cause.get('temporal_order', 'N/A')})")


# Run all tests
if __name__ == "__main__":
    print("Running Root Cause Analyzer Tests...\n")
    
    try:
        test_categories()
        test_auto_suggest_labels()
        test_feature_extraction()
        test_model_training()
        test_prediction()
        test_analyze_alert()
        test_temporal_priority()
        
        print("\n" + "="*50)
        print("✅ ALL TESTS PASSED")
        print("="*50)
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        raise
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        raise
