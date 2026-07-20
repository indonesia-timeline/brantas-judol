#!/usr/bin/env python3
"""
Layer 3: HTTP Probe - Ambil title, meta description, metadata dari domain live.
"""

import asyncio
import sys
import time
from typing import Optional

import httpx
from bs4 import BeautifulSoup

_progress_last_print: dict[str, float] = {}

def _fmt_elapsed(secs: float) -> str:
    m, s = divmod(int(secs), 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"

def render_progress(label: str, done: int, total: int, stats_str: str = '',
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


async def probe_domain(domain: str, client: httpx.AsyncClient) -> dict:
    result = {
        'domain': domain,
        'status_code': None,
        'title': None,
        'description': None,
        'keywords': None,
        'content_type': None,
        'server': None,
        'final_url': None,
        'response_time_ms': None,
        'error': None,
    }

    urls = [f'https://{domain}', f'http://{domain}']

    for i, url in enumerate(urls):
        try:
            start = time.monotonic()
            resp = await client.get(url, timeout=httpx.Timeout(connect=8.0, read=8.0, write=5.0))
            elapsed = (time.monotonic() - start) * 1000

            result['status_code'] = resp.status_code
            ctype = resp.headers.get('content-type', '')
            result['content_type'] = ctype.split(';')[0].strip() if ctype else None
            result['server'] = resp.headers.get('server')
            result['final_url'] = str(resp.url)
            result['response_time_ms'] = round(elapsed, 1)

            if 'text/html' in ctype:
                soup = BeautifulSoup(resp.text, 'html.parser')
                if soup.title and soup.title.string:
                    result['title'] = soup.title.string.strip()[:500]
                for name in ('description', 'Description'):
                    meta = soup.find('meta', attrs={'name': name})
                    if meta and meta.get('content'):
                        result['description'] = meta['content'].strip()[:500]
                        break
                meta_kw = soup.find('meta', attrs={'name': 'keywords'})
                if meta_kw and meta_kw.get('content'):
                    result['keywords'] = meta_kw['content'].strip()[:500]

            return result

        except (httpx.ConnectError, httpx.ConnectTimeout):
            if i == len(urls) - 1:
                result['error'] = 'connect_error'
        except httpx.ReadTimeout:
            if i == len(urls) - 1:
                result['error'] = 'timeout'
        except httpx.RemoteProtocolError:
            if i == len(urls) - 1:
                result['error'] = 'protocol_error'
        except Exception as e:
            if i == len(urls) - 1:
                result['error'] = type(e).__name__[:60]

    return result


async def probe_domains(live_domains: list, concurrency: int = 50) -> list:
    if not live_domains:
        return []

    sem = asyncio.Semaphore(concurrency)
    results: list = []
    lock = asyncio.Lock()
    total = len(live_domains)
    done = 0
    _start = time.monotonic()

    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    timeout = httpx.Timeout(connect=8.0, read=8.0, write=5.0, pool=5.0)

    async with httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True) as client:
        async def probe(d: str):
            nonlocal done
            async with sem:
                r = await probe_domain(d, client)
                async with lock:
                    results.append(r)
                    done += 1
                    ok_count = sum(1 for x in results if x['status_code'] is not None)
                    err_count = done - ok_count
                    elapsed = time.monotonic() - _start
                    render_progress('Probe', done, total,
                                    f"OK:{ok_count} ERR:{err_count}", elapsed=elapsed)

        tasks = [asyncio.create_task(probe(d)) for d in live_domains]
        await asyncio.gather(*tasks)

    print()
    ok_count = sum(1 for r in results if r['status_code'] is not None)
    print(f"[Probe] Selesai: {ok_count}/{total} HTTP OK, {total - ok_count} gagal")
    return results
