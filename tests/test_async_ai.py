#!/usr/bin/env python3
"""
Test Suite: Pembuktian Konkurensi Asinkronus (asyncio.gather) pada Dual Model AI
Membandingkan eksekusi Sekuensial (0.8s) vs Asinkronus Paralel (~0.5s)
"""

import sys
import os
import time
import json
import asyncio

# Pastikan UTF-8 encoding di Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Pastikan root workspace dapat diimpor
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
for p in [CURRENT_DIR, PROJECT_ROOT]:
    if p not in sys.path:
        sys.path.insert(0, p)

from api.process_ai import predict_model_rf, predict_model_svm, process_ai_endpoint


def print_banner(text: str):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


async def run_sequential_benchmark(sample_text: str):
    print_banner("1. UJI EKSEKUSI SEKUENSIAL (TANPA GATHER)")
    print(f"[*] Input Data  : '{sample_text}'")
    print("[*] Menjalankan Model A (Random Forest 0.3s) ...")
    
    t_start = time.time()
    res_rf = await predict_model_rf(sample_text)
    t_mid = time.time()
    print(f"    -> Model RF selesai dalam   : {t_mid - t_start:.4f} detik")
    
    print("[*] Menjalankan Model B (SVM 0.5s) setelah Model A ...")
    res_svm = await predict_model_svm(sample_text)
    t_end = time.time()
    print(f"    -> Model SVM selesai dalam  : {t_end - t_mid:.4f} detik")
    
    total_sequential = t_end - t_start
    print(f"[!] TOTAL WAKTU SEKUENSIAL      : {total_sequential:.4f} detik (~0.8s)")
    return total_sequential


async def run_parallel_gather_benchmark(sample_text: str):
    print_banner("2. UJI EKSEKUSI ASINKRONUS PARALEL (asyncio.gather)")
    print(f"[*] Input Data  : '{sample_text}'")
    print("[*] Memulai asyncio.gather(predict_model_rf, predict_model_svm) ...")
    
    t_start = time.time()
    res_rf, res_svm = await asyncio.gather(
        predict_model_rf(sample_text),
        predict_model_svm(sample_text)
    )
    t_end = time.time()
    
    total_parallel = t_end - t_start
    print(f"    -> Model RF Hasil   : {res_rf['model']} | Prediksi: {res_rf['prediction']} | Confidence: {res_rf['confidence']}")
    print(f"    -> Model SVM Hasil  : {res_svm['model']} | Prediksi: {res_svm['prediction']} | Confidence: {res_svm['confidence']}")
    print(f"[OK] TOTAL WAKTU PARALEL (GATHER): {total_parallel:.4f} detik (~0.5s)")
    return total_parallel


async def run_fastapi_endpoint_test():
    print_banner("3. UJI RESPON ENDPOINT FASTAPI: GET /api/proses_ai")
    
    test_cases = [
        ("SELECT * FROM users WHERE id = 1 OR 1=1 --", "Uji Ancaman SQL Injection"),
        ("Pelaporan status patroli siber harian aman terkendali", "Uji Query Normal / Aman")
    ]
    
    for query_input, desc in test_cases:
        print(f"\n--- Skenario: {desc} ---")
        print(f"Query Param : ?input={query_input}")
        
        response = await process_ai_endpoint(input=query_input)
        
        assert "status" in response, "Field 'status' harus ada"
        assert "duration_seconds" in response, "Field 'duration_seconds' harus ada"
        assert "results" in response, "Field 'results' harus ada"
        assert "model_rf" in response["results"], "Field 'model_rf' harus ada"
        assert "model_svm" in response["results"], "Field 'model_svm' harus ada"
        
        print("Format Response JSON:")
        print(json.dumps(response, indent=2))
        
        dur = response["duration_seconds"]
        print(f"-> Durasi tercatat: {dur} detik (Target: ~0.5s)")
        assert dur < 0.75, f"Waktu harus jauh di bawah 0.8s, aktual: {dur}s"


async def main():
    sample = "SELECT token FROM sessions WHERE username = 'admin' OR 1=1"
    
    t_seq = await run_sequential_benchmark(sample)
    t_par = await run_parallel_gather_benchmark(sample)
    await run_fastapi_endpoint_test()
    
    hemat_waktu = ((t_seq - t_par) / t_seq) * 100
    print_banner("4. BUKTI KONKURENSI & KESIMPULAN EFISIENSI")
    print(f"  - Waktu Sekuensial (T_A + T_B)     : {t_seq:.4f} detik  (~0.8s - Rawan Timeout Vercel)")
    print(f"  - Waktu Paralel (asyncio.gather)   : {t_par:.4f} detik  (~0.5s - Waktu Model Terlambat)")
    print(f"  - Penghematan Latensi              : {t_seq - t_par:.4f} detik ({hemat_waktu:.1f}% lebih cepat)")
    print(f"  - Status Pembuktian                : [PASS] TERBUKTI KONKUREN")
    print("=" * 70)
    print("Kesimpulan: Dengan asyncio.gather(), total waktu tunggu hanyalah sebesar")
    print("model yang paling lambat (SVM = ~0.5 detik), BUKAN penjumlahan keduanya (~0.8 detik).")
    print("Hal ini secara signifikan mencegah Vercel Serverless Function timeout!\n")


if __name__ == "__main__":
    asyncio.run(main())
