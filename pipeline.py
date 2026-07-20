#!/usr/bin/env python3
"""
Pipeline Utama: CT Extract → DNS Check → Probe → LLM Analisis → Investigasi → Final JSON.
Intermediate data hanya di temp runner, hasil akhir diupload ke GitHub sebagai data_{round}.json.
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone

import httpx

from ct_dns_check import (
    collector,
    run_dns_checks,
    load_checkpoint,
    save_checkpoint,
    _close_dns_resolver,
    github_upload,
    CHECKPOINT_PATH,
)

from probe import probe_domains
from analyze import analyze_domains
from investigate import investigate_domains

LOG_URL = "https://ct.googleapis.com/logs/us1/argon2026h2"
TARGET_PER_ROUND = 1000
DEFAULT_START_INDEX = 1


async def main():
    print("=" * 60)
    print("  BRANTAS JUDOL - FULL PIPELINE")
    print("  CT Extract → DNS → Probe → LLM → Investigate → Final JSON")
    print("=" * 60)
    print(f"  Log: {LOG_URL}")
    print(f"  Target: {TARGET_PER_ROUND} domain/round")
    print(f"  Checkpoint: {CHECKPOINT_PATH}")
    print("=" * 60)

    round_start = time.monotonic()

    async with httpx.AsyncClient() as client:
        start_index = await load_checkpoint(client, default_index=DEFAULT_START_INDEX)
    print(f"[Pipeline] Starting from CT index: {start_index:,}\n")

    # ── Layer 1: CT Domain Extraction ──
    t1 = time.monotonic()
    print("─" * 50)
    print("[Layer 1] CT LOG EXTRACTION")
    print("─" * 50)
    next_index, raw_domains = await collector(LOG_URL, start_index, TARGET_PER_ROUND)
    await save_checkpoint(next_index)
    print(f"[Layer 1] Waktu: {time.monotonic() - t1:.1f}s\n")

    if not raw_domains:
        print("[Pipeline] Tidak ada domain dari CT log, selesai.")
        await _close_dns_resolver()
        return

    # ── Layer 2: DNS Check ──
    t2 = time.monotonic()
    print("─" * 50)
    print(f"[Layer 2] DNS CHECK ({len(raw_domains)} domain)")
    print("─" * 50)
    dns_results = await run_dns_checks(raw_domains)
    print(f"[Layer 2] Waktu: {time.monotonic() - t2:.1f}s")
    print(f"[Layer 2] Hasil: {len(dns_results['ok'])} resolve, {len(dns_results['fail'])} gagal\n")

    if not dns_results['ok']:
        print("[Pipeline] Tidak ada domain yang resolve, selesai.")
        await _close_dns_resolver()
        return

    # ── Layer 3: HTTP Probe ──
    t3 = time.monotonic()
    print("─" * 50)
    print(f"[Layer 3] HTTP PROBE ({len(dns_results['ok'])} domain)")
    print("─" * 50)
    probe_results = await probe_domains(dns_results['ok'])
    print(f"[Layer 3] Waktu: {time.monotonic() - t3:.1f}s\n")

    # ── Layer 4: LLM Analysis ──
    t4 = time.monotonic()
    print("─" * 50)
    print("[Layer 4] LLM ANALYSIS (Gemini 2.5 Flash)")
    print("─" * 50)
    analysis_results = analyze_domains(probe_results)
    print(f"[Layer 4] Waktu: {time.monotonic() - t4:.1f}s\n")

    # ── Layer 5: Investigation ──
    t5 = time.monotonic()
    print("─" * 50)
    print("[Layer 5] INVESTIGATION (urlscan.io + Wayback Machine)")
    print("─" * 50)
    final_results = await investigate_domains(analysis_results)
    print(f"[Layer 5] Waktu: {time.monotonic() - t5:.1f}s\n")

    # ── Build & Upload Final JSON ──
    gambling_count = sum(
        1 for d in final_results
        if d.get('analysis', {}).get('is_gambling')
    )
    probe_ok = sum(1 for d in final_results if d.get('status_code') is not None)

    round_data = {
        'round_index': start_index,
        'updated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'duration_seconds': round(time.monotonic() - round_start, 1),
        'stats': {
            'total_ct_domains': len(raw_domains),
            'dns_live': len(dns_results['ok']),
            'dns_dead': len(dns_results['fail']),
            'probe_ok': probe_ok,
            'probe_fail': len(probe_results) - probe_ok,
            'gambling_detected': gambling_count,
        },
        'domains': final_results,
    }

    folder = f"round_{start_index}"
    filename = f"{folder}/data_{start_index}.json"
    json_content = json.dumps(round_data, indent=2)

    async with httpx.AsyncClient() as client:
        await github_upload(filename, json_content, client)

    total_time = time.monotonic() - round_start
    print("=" * 60)
    print(f"  PIPELINE SELESAI dalam {total_time:.1f}s")
    print(f"  Upload: {filename}")
    print(f"  Statistik:")
    print(f"    CT domains : {len(raw_domains)}")
    print(f"    DNS live   : {len(dns_results['ok'])}")
    print(f"    Probe ok   : {probe_ok}")
    print(f"    Judi       : {gambling_count}")
    print("=" * 60)

    await _close_dns_resolver()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Pipeline dihentikan.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Pipeline error: {e}")
        sys.exit(1)
