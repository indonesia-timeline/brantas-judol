#!/usr/bin/env python3
"""
CT Domain Extractor + DNS Check - Ambil domain dari CT log, cek DNS, kirim ke GitHub via API.
Tanpa file lokal (kecuali checkpoint kecil).
"""

import asyncio
import base64
import os
import re
import json
import sys
import time
import random
import socket
import warnings
from typing import Set, Optional, Dict, Any
from urllib.parse import urlparse

import httpx
import aiodns
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

CHECKPOINT_PATH = 'checkpoint_ct_dns.json'
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
GITHUB_REPO = os.environ.get('GITHUB_REPO', 'github.com/anomalyco/brantas-judol')

_dns_resolver: Optional[aiodns.DNSResolver] = None

def _get_dns_resolver() -> aiodns.DNSResolver:
    global _dns_resolver
    if _dns_resolver is None:
        _dns_resolver = aiodns.DNSResolver(timeout=5.0)
    return _dns_resolver

async def _close_dns_resolver():
    global _dns_resolver
    if _dns_resolver is not None:
        await _dns_resolver.close()
        _dns_resolver = None

def _parse_repo(repo: str):
    path = urlparse(f"https://{repo}").path.strip('/')
    parts = path.split('/')
    return parts[0], parts[1]

def load_checkpoint(path: str = CHECKPOINT_PATH, default_index: int = 1) -> int:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return int(data.get('last_index', default_index))
    except Exception:
        return default_index

def save_checkpoint(last_index: int, path: str = CHECKPOINT_PATH):
    tmp_path = path + '.tmp'
    try:
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump({'last_index': last_index, 'updated_at': time.time()}, f)
        os.replace(tmp_path, path)
    except Exception as e:
        print(f"[!] Gagal menyimpan checkpoint: {e}")

async def github_upload(filename: str, content: str, client: httpx.AsyncClient):
    if not GITHUB_TOKEN:
        print("[!] GITHUB_TOKEN tidak di-set, skip upload")
        return
    owner, repo = _parse_repo(GITHUB_REPO)
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}"
    headers = {
        'Authorization': f'Bearer {GITHUB_TOKEN}',
        'Accept': 'application/vnd.github.v3+json',
    }
    data = {
        'message': f'add {filename}',
        'content': base64.b64encode(content.encode()).decode(),
        'branch': 'main',
    }
    for attempt in range(3):
        try:
            resp = await client.put(url, json=data, headers=headers,
                                    timeout=httpx.Timeout(connect=10, read=30, write=30, pool=5))
            if resp.status_code == 201:
                print(f"[GitHub] Upload {filename} sukses")
                return
            if resp.status_code == 422:
                print(f"[GitHub] {filename} sudah ada, skip")
                return
            if resp.status_code in (403, 429):
                wait = 2 ** attempt
                print(f"[GitHub] Rate limit, tunggu {wait}s...")
                await asyncio.sleep(wait)
                continue
            print(f"[GitHub] Gagal ({resp.status_code}): {resp.text[:200]}")
            return
        except Exception as e:
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)
                continue
            print(f"[GitHub] Error: {e}")

_progress_last_print: Dict[str, float] = {}

def _fmt_elapsed(secs: float) -> str:
    m, s = divmod(int(secs), 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"

def render_progress_bar(label: str, done: int, total: int, stats_str: str = '',
                        width: int = 30, min_interval: float = 0.1, elapsed: float = 0.0):
    total = max(total, 1)
    now = time.monotonic()
    last = _progress_last_print.get(label, 0.0)
    is_final = done >= total
    if not is_final and (now - last) < min_interval:
        return
    _progress_last_print[label] = now

    pct = min(done / total, 1.0)
    filled = int(width * pct)
    bar = '█' * filled + '░' * (width - filled)
    time_str = f"T:{_fmt_elapsed(elapsed)}" if elapsed else ''
    line = (f"\r[{label}] |{bar}| "
            f"{done}/{total} ({pct*100:5.1f}%) {stats_str} {time_str}")
    sys.stdout.write(line)
    sys.stdout.flush()

def _backoff(attempt: int, base: float = 1.0, cap: float = 10.0) -> float:
    return min(cap, base * 2 ** attempt) * random.uniform(0.5, 1.5)

async def dns_check(domain: str, attempts: int = 2, base_timeout: float = 5.0) -> bool:
    resolver = _get_dns_resolver()
    for i in range(attempts):
        try:
            await asyncio.wait_for(
                resolver.getaddrinfo(domain, socket.AF_UNSPEC, port=80),
                timeout=base_timeout,
            )
            return True
        except (asyncio.TimeoutError, OSError, aiodns.error.DNSError):
            pass
        if i < attempts - 1:
            await asyncio.sleep(_backoff(i, base=0.4, cap=2.0))
    return False

def normalize_domain(raw: str) -> Optional[str]:
    raw = raw.strip().lower()
    if not raw or raw.startswith('.'):
        return None
    if raw.startswith('*.'):
        raw = raw[2:]
    if not re.match(r'^[a-z0-9.-]+$', raw):
        return None
    if raw.endswith(('.local', '.test', '.invalid', '.localhost', '.onion')):
        return None
    if len(raw) < 4 or '.' not in raw:
        return None
    return raw

def _read_uint(data: bytes, offset: int, nbytes: int) -> int:
    return int.from_bytes(data[offset:offset + nbytes], 'big')

def extract_cert_der_from_entry(leaf_input: bytes, extra_data: bytes) -> Optional[bytes]:
    try:
        if len(leaf_input) < 12:
            return None
        entry_type = _read_uint(leaf_input, 10, 2)

        if entry_type == 0:
            length = _read_uint(leaf_input, 12, 3)
            cert_der = leaf_input[15:15 + length]
            if len(cert_der) != length:
                return None
            x509.load_der_x509_certificate(cert_der, default_backend())
            return cert_der

        elif entry_type == 1:
            if len(extra_data) < 3:
                return None
            length = _read_uint(extra_data, 0, 3)
            cert_der = extra_data[3:3 + length]
            if len(cert_der) != length:
                return None
            x509.load_der_x509_certificate(cert_der, default_backend())
            return cert_der
    except Exception:
        pass

    return _brute_force_extract_der(leaf_input) or _brute_force_extract_der(extra_data)

def _brute_force_extract_der(data: bytes) -> Optional[bytes]:
    for marker in (b'\x30\x82', b'\x30\x81'):
        pos = data.find(marker)
        if pos == -1:
            continue
        if marker == b'\x30\x82' and pos + 4 <= len(data):
            length = int.from_bytes(data[pos + 2:pos + 4], 'big')
            total = 4 + length
            if pos + total <= len(data):
                cert_der = data[pos:pos + total]
                try:
                    x509.load_der_x509_certificate(cert_der, default_backend())
                    return cert_der
                except Exception:
                    pass
        elif marker == b'\x30\x81' and pos + 3 <= len(data):
            length = data[pos + 2]
            total = 3 + length
            if pos + total <= len(data):
                cert_der = data[pos:pos + total]
                try:
                    x509.load_der_x509_certificate(cert_der, default_backend())
                    return cert_der
                except Exception:
                    pass
    return None

def extract_san_from_cert(cert_der: bytes) -> Set[str]:
    domains = set()
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
    except Exception:
        return set()

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                norm = normalize_domain(name.value)
                if norm:
                    domains.add(norm)
    except x509.ExtensionNotFound:
        pass

    if not domains:
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn:
                norm = normalize_domain(cn[0].value)
                if norm:
                    domains.add(norm)
        except Exception:
            pass

    return domains

def process_entry(entry: Dict[str, Any]) -> Set[str]:
    try:
        leaf_input = base64.b64decode(entry['leaf_input'])
        extra_data = base64.b64decode(entry.get('extra_data', '')) if entry.get('extra_data') else b''
        cert_der = extract_cert_der_from_entry(leaf_input, extra_data)
        if cert_der:
            return extract_san_from_cert(cert_der)
        return set()
    except Exception:
        return set()

async def fetch_batch(client: httpx.AsyncClient, log_url: str, start: int, count: int = 200) -> list:
    end = start + count - 1
    url = f"{log_url}/ct/v1/get-entries"
    params = {'start': start, 'end': end}
    for attempt in range(3):
        try:
            resp = await client.get(url, params=params, timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0))
            if resp.status_code in (429, 502, 503):
                await asyncio.sleep(_backoff(attempt))
                continue
            resp.raise_for_status()
            return resp.json().get('entries', [])
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError):
            await asyncio.sleep(_backoff(attempt))
            continue
        except Exception as e:
            print(f"[!] Fetch error {start}-{end}: {e}")
            return []
    print(f"[!] Gagal fetch {start}-{end} setelah 3 percobaan")
    return []

async def collector(log_url: str, start_index: int, target_domains: int) -> tuple[int, set]:
    print(f"[Collector] Mulai mengumpulkan {target_domains} domain unik dari index {start_index:,}...")
    log_size = None
    collected: set = set()
    consecutive_empty = 0
    max_empty = 50
    batch_size = 200
    total_domain_mentions = 0
    entries_ok = 0
    entries_failed = 0
    position = start_index
    _start_time = time.monotonic()

    limits = httpx.Limits(max_connections=5, max_keepalive_connections=5)
    timeout = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=True) as client:
        try:
            resp = await client.get(f"{log_url}/ct/v1/get-sth")
            resp.raise_for_status()
            log_size = resp.json().get('tree_size')
            print(f"[Collector] Ukuran log: {log_size:,} entri")
        except Exception as e:
            print(f"[!] Gagal mendapatkan ukuran log: {e}")

        while len(collected) < target_domains:
            start = position

            if log_size and start >= log_size:
                try:
                    resp = await client.get(f"{log_url}/ct/v1/get-sth")
                    resp.raise_for_status()
                    log_size = resp.json().get('tree_size')
                except Exception:
                    pass
                if log_size and start >= log_size:
                    print(f"\n[Collector] Menunggu entri baru di log (posisi {start:,} >= ukuran log {log_size:,})...")
                    await asyncio.sleep(10)
                    continue

            entries = await fetch_batch(client, log_url, start, batch_size)
            position += batch_size

            if not entries:
                consecutive_empty += 1
                if consecutive_empty >= max_empty:
                    print(f"[Collector] {max_empty} batch berturut-turut tanpa entri, berhenti round ini.")
                    break
                continue

            new_in_batch = 0
            for entry in entries:
                domains = process_entry(entry)
                if domains:
                    entries_ok += 1
                    total_domain_mentions += len(domains)
                else:
                    entries_failed += 1
                for d in domains:
                    if d not in collected:
                        collected.add(d)
                        new_in_batch += 1
                        if len(collected) >= target_domains:
                            break
                if len(collected) >= target_domains:
                    break

            if new_in_batch == 0:
                consecutive_empty += 1
            else:
                consecutive_empty = 0

            stats_str = f"@{start} +{new_in_batch} | unik:{len(collected)}/{target_domains}"
            render_progress_bar('Collector', len(collected), target_domains, stats_str,
                                elapsed=time.monotonic() - _start_time)

            if consecutive_empty >= max_empty:
                print(f"\n[Collector] {max_empty} batch tanpa domain baru, hentikan round ini.")
                break

    print()
    print(f"[Collector] Round selesai. Domain terkumpul: {len(collected)}")
    print(f"[Collector] Entri berhasil diekstrak: {entries_ok}, gagal/kosong: {entries_failed}")
    print(f"[Collector] Posisi CT log terakhir: {position:,} (akan jadi checkpoint)")
    if total_domain_mentions:
        dup_ratio = len(collected) / total_domain_mentions
        print(f"[Collector] Total kemunculan domain: {total_domain_mentions} "
              f"({'tinggi duplikasi' if dup_ratio < 0.1 else 'wajar'})")

    return position, collected

async def run_dns_checks(domains: set, concurrency: int = 100) -> dict:
    sem = asyncio.Semaphore(concurrency)
    lock = asyncio.Lock()
    results = {'ok': [], 'fail': []}
    total = len(domains)
    done = 0
    _start = time.monotonic()

    async def check(d: str):
        nonlocal done
        async with sem:
            ok = await dns_check(d)
            async with lock:
                done += 1
                if ok:
                    results['ok'].append(d)
                else:
                    results['fail'].append(d)
                elapsed = time.monotonic() - _start
                stats = f"OK:{len(results['ok'])} FAIL:{len(results['fail'])}"
                render_progress_bar('DNS', done, total, stats, elapsed=elapsed)
    tasks = [asyncio.create_task(check(d)) for d in domains]
    await asyncio.gather(*tasks)
    print()
    return results

async def main():
    LOG_URL = "https://ct.googleapis.com/logs/us1/argon2026h2"
    DEFAULT_START_INDEX = 1
    TARGET_PER_ROUND = 1000

    print("="*60)
    print(f"CT DOMAIN EXTRACTOR + DNS CHECK ({TARGET_PER_ROUND} DOMAIN/ROUND)")
    print("="*60)
    print(f"Log: {LOG_URL}")
    print(f"Target per round: {TARGET_PER_ROUND} domain unik")
    print(f"Checkpoint: {CHECKPOINT_PATH}")
    print(f"GitHub: {GITHUB_REPO}")
    print("="*60 + "\n")

    round_num = 0
    next_index = load_checkpoint(default_index=DEFAULT_START_INDEX)
    if next_index != DEFAULT_START_INDEX:
        print(f"[*] Melanjutkan dari checkpoint: index {next_index:,}\n")

    async with httpx.AsyncClient() as client:
        try:
            while True:
                round_num += 1
                round_start_index = next_index

                print(f"--- Round {round_num} | mulai index {round_start_index:,} ---")

                next_index, domains = await collector(LOG_URL, round_start_index, TARGET_PER_ROUND)

                save_checkpoint(next_index)

                if domains:
                    all_content = '\n'.join(sorted(domains)) + '\n'

                    print(f"[DNS] Cek {len(domains)} domain...")
                    dns_results = await run_dns_checks(domains)

                    live_content = '\n'.join(sorted(dns_results['ok'])) + '\n'

                    folder = f"round_{round_start_index}"
                    await github_upload(f"{folder}/domains_{round_start_index}.txt", all_content, client)
                    await github_upload(f"{folder}/dns_live_{round_start_index}.txt", live_content, client)

                    print(f"[DNS] Hasil: {len(dns_results['ok'])} resolve, {len(dns_results['fail'])} gagal")
                else:
                    print("[*] Tidak ada domain untuk dicek")

                print(f"[*] Round {round_num} selesai. Checkpoint: index {next_index:,}\n")
        except KeyboardInterrupt:
            print("\n[*] Dihentikan.")
        finally:
            await _close_dns_resolver()
            sys.exit(0)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Dihentikan.")
        sys.exit(0)
