"""
Vercel Serverless Function: High-Performance Concurrent AI Threat Analysis
Framework: FastAPI with asyncio.gather()
Endpoint: GET /api/proses_ai or /api/process_ai?input=<data_teks>
"""

import time
import asyncio
from typing import Optional
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Sentinel AI Concurrent Threat Engine",
    description="Dual-Model Asynchronous Threat Classifier (Random Forest & SVM)",
    version="1.0.0"
)

# Indikator signature serangan umum (SQLi, XSS, PrivEsc, Command Injection)
THREAT_KEYWORDS = [
    "union select", "or 1=1", "drop table", "exec", "<script>",
    "admin' --", "sleep(", "benchmark(", "xp_cmdshell", "system(",
    "select *", "information_schema", "etc/passwd"
]


async def predict_model_rf(input_text: str) -> dict:
    """
    Simulasi Model A: Random Forest (RF)
    Karakteristik: Evaluasi pohon keputusan ensemble cepat.
    Delay simulasi: 0.3 detik.
    """
    await asyncio.sleep(0.3)
    
    text_lower = input_text.lower()
    is_threat = any(kw in text_lower for kw in THREAT_KEYWORDS)
    
    confidence = 0.94 if is_threat else 0.98
    prediction = "BAHAYA" if is_threat else "AMAN"
    
    return {
        "model": "Random Forest (RF)",
        "prediction": prediction,
        "confidence": confidence,
        "coincidence": confidence  # Field sesuai spesifikasi soal
    }


async def predict_model_svm(input_text: str) -> dict:
    """
    Simulasi Model B: Support Vector Machine (SVM)
    Karakteristik: Hyperplane classification boundary kompleks.
    Delay simulasi: 0.5 detik (model paling lambat).
    """
    await asyncio.sleep(0.5)
    
    text_lower = input_text.lower()
    is_threat = any(kw in text_lower for kw in THREAT_KEYWORDS)
    
    confidence = 0.91 if is_threat else 0.96
    prediction = "BAHAYA" if is_threat else "AMAN"
    
    return {
        "model": "Support Vector Machine (SVM)",
        "prediction": prediction,
        "confidence": confidence,
        "coincidence": confidence  # Field sesuai spesifikasi soal
    }


@app.get("/api/proses_ai")
@app.get("/api/process_ai")
@app.get("/api/proces_ai")
@app.get("/")
async def process_ai_endpoint(
    input: str = Query(..., description="Data teks/kueri untuk analisis keamanan")
):
    """
    Endpoint pemroses AI asinkronus menggunakan asyncio.gather().
    Kedua model (RF 0.3s & SVM 0.5s) dipanggil secara paralel sehingga
    total waktu respons ≈ max(0.3s, 0.5s) = ~0.5s, bukan 0.8s.
    """
    try:
        start_time = time.time()
        
        # Eksekusi konkurensi paralel dengan asyncio.gather
        rf_result, svm_result = await asyncio.gather(
            predict_model_rf(input),
            predict_model_svm(input)
        )
        
        end_time = time.time()
        duration_seconds = round(end_time - start_time, 4)
        
        return {
            "status": "success",
            "duration_seconds": duration_seconds,
            "input_received": input,
            "results": {
                "model_rf": rf_result,
                "model_svm": svm_result
            }
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": str(e),
                "duration_seconds": 0.0,
                "results": {}
            }
        )
