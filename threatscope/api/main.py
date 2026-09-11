import time
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any

from threatscope.ml.model import ThreatScopeClassifier
from threatscope.sandbox.engine import BehavioralSandbox

app = FastAPI(
    title="ThreatScope API",
    description="Hybrid ML + Dynamic Behavioral URL Security Engine",
    version="1.0.0"
)

classifier = ThreatScopeClassifier()
sandbox = BehavioralSandbox(timeout_ms=12000)

class ScanRequest(BaseModel):
    url: str
    force_sandbox: bool = False
    sandbox_threshold: float = 0.60

class ScanResponse(BaseModel):
    url: str
    verdict: str
    overall_threat_score: float
    analysis_layers: Dict[str, Any]
    execution_time_seconds: float

@app.get("/health")
def health_check():
    return {"status": "healthy", "engine": "ThreatScope", "model_loaded": classifier.model is not None}

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url(payload: ScanRequest):
    start_total = time.time()
    url = payload.url.strip()

    t0 = time.time()
    ml_result = classifier.predict(url)
    l1_time = round(time.time() - t0, 4)

    layers = {
        "layer_1_ml": {
            "execution_time_seconds": l1_time,
            "malicious_probability": ml_result["malicious_probability"],
            "features_extracted": ml_result["feature_count"],
            "top_features": ml_result["top_features"]
        },
        "layer_2_behavioral_sandbox": None
    }

    final_score = ml_result["malicious_probability"]
    escalated_to_sandbox = payload.force_sandbox or (final_score >= payload.sandbox_threshold)

    if escalated_to_sandbox:
        try:
            sandbox_res = await sandbox.analyze_url(url)
            layers["layer_2_behavioral_sandbox"] = sandbox_res
            final_score = round((0.40 * ml_result["malicious_probability"]) + (0.60 * sandbox_res["threat_score"]), 4)
        except Exception as e:
            layers["layer_2_behavioral_sandbox"] = {"status": "error", "detail": str(e)}

    verdict = "MALICIOUS" if final_score >= 0.50 else "BENIGN"
    if 0.40 <= final_score < 0.50:
        verdict = "SUSPICIOUS"

    return ScanResponse(
        url=url,
        verdict=verdict,
        overall_threat_score=final_score,
        analysis_layers=layers,
        execution_time_seconds=round(time.time() - start_total, 3)
    )
