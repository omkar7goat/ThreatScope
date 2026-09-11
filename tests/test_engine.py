import pytest
from threatscope.ml.feature_extractor import extract_features_from_url
from threatscope.ml.model import ThreatScopeClassifier

def test_feature_extraction_count():
    url = "https://secure-login.example.com/account/auth?token=12345"
    features = extract_features_from_url(url)
    assert len(features) >= 55
    assert features["count_question"] == 1
    assert features["is_https"] == 1
    assert features["kw_login"] == 1

def test_classifier_predict_benign():
    clf = ThreatScopeClassifier()
    res = clf.predict("https://www.wikipedia.org")
    assert "malicious_probability" in res
    assert res["malicious_probability"] < 0.60

def test_classifier_predict_malicious_indicator():
    clf = ThreatScopeClassifier()
    res = clf.predict("http://192.168.1.1/secure-banking-login.xyz/update.exe")
    assert res["malicious_probability"] > 0.40
