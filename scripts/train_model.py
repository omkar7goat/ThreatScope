import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from threatscope.ml.feature_extractor import extract_features_from_url, FEATURE_NAMES

def generate_synthetic_training_set(num_samples: int = 1200):
    benign_samples = [
        "https://www.google.com/search?q=cybersecurity",
        "https://github.com/torvalds/linux",
        "https://en.wikipedia.org/wiki/Random_forest",
        "https://aws.amazon.com/console/",
        "https://stackoverflow.com/questions/tagged/python",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://www.nytimes.com/section/technology",
        "https://medium.com/@developer/fastapi-production-guide",
        "https://cloud.google.com/run/docs",
        "https://hub.docker.com/_/python"
    ]

    malicious_samples = [
        "http://secure-login-update.account-verification.xyz/bank/login.php?user=admin",
        "http://192.168.1.105/auth/signin-token-verification.asp?session=expired",
        "http://metamask-wallet-claim-bonus.fit/connect/auth.html#wallet",
        "http://paypal.account-recovery-alert.club/webscr?cmd=_login-run",
        "http://binance.security-credential-portal.top/verify.html?auth=token",
        "http://apple-id-verify.support-unlock-device.cc/update/security.php",
        "http://104.244.42.1/malware/download.exe",
        "http://free-gift-crypto-claim.icu/airdrop?id=92847",
        "http://microsoft-office365-verify.buzz/login.php?ref=mail",
        "http://bank-of-america-online.country/secure/update-profile"
    ]

    rows = []
    labels = []

    for _ in range(num_samples // 2):
        b = np.random.choice(benign_samples)
        m = np.random.choice(malicious_samples)
        rows.append(extract_features_from_url(f"{b}?rand={np.random.randint(1000, 99999)}"))
        labels.append(0)
        rows.append(extract_features_from_url(f"{m}&salt={np.random.randint(1000, 99999)}"))
        labels.append(1)

    return pd.DataFrame(rows)[FEATURE_NAMES], np.array(labels)

def train_and_save():
    print("[*] Generating training features for ThreatScope Random Forest...")
    X, y = generate_synthetic_training_set(1200)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print(f"[*] Training Random Forest Classifier on {len(X_train)} samples...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_split=4, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"[+] Model Training Completed. Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, preds, target_names=["Benign", "Malicious"]))

    model_dir = os.path.join(os.path.dirname(__file__), "..", "threatscope", "ml", "models")
    os.makedirs(model_dir, exist_ok=True)
    out_path = os.path.join(model_dir, "threatscope_rf_model.joblib")
    joblib.dump(clf, out_path)
    print(f"[+] Model saved to: {out_path}")

if __name__ == "__main__":
    train_and_save()
