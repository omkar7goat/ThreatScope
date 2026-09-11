# 🛡️ ThreatScope: Hybrid URL Threat Detection Engine

> **Two-tier cybersecurity architecture combining a 65-feature Random Forest Machine Learning pre-filter with containerized dynamic behavioral sandboxing via Playwright.**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Playwright](https://img.shields.io/badge/Playwright-Dynamic_Sandbox-2EAD33?style=flat&logo=playwright&logoColor=white)](https://playwright.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📌 Architecture

```
Incoming URL
     │
     ▼
[ Layer 1: ML Pre-Filter ] ─── (0.1–0.5s) ───► Benign / Low Risk (Allowed)
     │ (Suspicious Score >= 0.60)
     ▼
[ Layer 2: Behavioral Sandbox ] ─────────────► Threat Confirmed / Quarantined
  (Isolated Playwright in Docker)
```

1. **Layer 1 (ML Pre-Filter):** Extracts 65 lexical, structural, and entropy features from the URL string. Employs a Random Forest model for sub-second classification (0.1–0.5s).
2. **Layer 2 (Dynamic Sandbox):** Containerized headless Playwright browser that monitors DOM form harvesting (passwords, credit cards), crypto-mining signatures (Coinhive, WebAssembly), and evasive multi-hop redirect chains.

---

## 📂 Repository Structure

```
ThreatScope/
├── .github/workflows/ci.yml       # GitHub Actions CI pipeline
├── docker/
│   └── Dockerfile                 # Headless Playwright + FastAPI container
├── scripts/
│   └── train_model.py             # Feature training script
├── tests/
│   └── test_engine.py             # Pytest suite
├── threatscope/
│   ├── __init__.py
│   ├── api/
│   │   └── main.py                # FastAPI endpoints
│   ├── ml/
│   │   ├── feature_extractor.py   # 65 lexical/entropy feature extractor
│   │   ├── model.py               # Inference wrapper & heuristic fallback
│   │   └── models/
│   │       └── threatscope_rf_model.joblib # Serialized model weights
│   └── sandbox/
│       └── engine.py              # Playwright dynamic sandboxing engine
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## 🚀 Quickstart

### Run with Docker Compose
```bash
docker-compose up --build
```
The API will be available at `http://localhost:8000`. Interactive docs are at `http://localhost:8000/docs`.

### Local Setup
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium
python scripts/train_model.py
uvicorn threatscope.api.main:app --reload --port 8000
```
