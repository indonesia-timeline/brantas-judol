#!/usr/bin/env python3
"""
Layer 5: Investigasi - urlscan.io search/scan + Wayback Machine.
"""

import asyncio
import json
import os
import sys
import time

import httpx


class URLScanClient:
    def __init__(self):
        self.api_key = os.environ.get('URLSCAN_API_KEY', '')
        self.headers = {
            'API-Key': self.api_key,
            'Content-Type': 'application/json',
        }
        self.base = 'https://urlscan.io/api/v1'

    async def search(self, domain: str, client: httpx.AsyncClient) -> dict:
        if not self.api_key:
            return {'found': False, 'error': 'no_api_key'}
        try:
            resp = await client.get(
                f'{self.base}/search/',
                params={'q': f'domain:{domain}', 'size': 3},
                headers=self.headers,
                timeout=15.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                results = data.get('results', [])
                if results:
                    r = results[0]
                    return {
                        'found': True,
                        'uuid': r.get('task', {}).get('uuid'),
                        'screenshot': f"https://urlscan.io/screenshots/{r.get('task', {}).get('uuid')}.png",
                        'page_url': r.get('page', {}).get('url'),
                        'ip': r.get('page', {}).get('ip'),
                        'country': r.get('page', {}).get('country'),
                        'verdict': r.get('verdict', {}).get('overall', {}).get('malicious'),
                        'scan_date': r.get('task', {}).get('time'),
                        'technologies': [s.get('name') for s in (r.get('page', {}).get('techs') or [])],
                    }
            return {'found': False}
        except Exception as e:
            return {'found': False, 'error': str(e)[:100]}

    async def submit_scan(self, domain: str, client: httpx.AsyncClient) -> dict:
        if not self.api_key:
            return {'submitted': False, 'error': 'no_api_key'}
        try:
            resp = await client.post(
                f'{self.base}/scan/',
                headers=self.headers,
                json={'url': f'https://{domain}', 'visibility': 'public'},
                timeout=30.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                uuid = data.get('uuid')
                return {
                    'submitted': True,
                    'uuid': uuid,
                    'result_url': data.get('result'),
                }
            return {'submitted': False, 'error': f'http_{resp.status_code}'}
        except Exception as e:
            return {'submitted': False, 'error': str(e)[:100]}

    async def poll_result(self, uuid: str, client: httpx.AsyncClient, timeout: float = 60.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                resp = await client.get(
                    f'{self.base}/result/{uuid}/',
                    timeout=15.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        'status': 'done',
                        'screenshot': data.get('task', {}).get('screenshotURL'),
                        'ip': data.get('page', {}).get('ip'),
                        'country': data.get('page', {}).get('country'),
                        'technologies': list(data.get('meta', {}).get('processors', {}).get('techs', {}).keys()),
                        'verdict': data.get('verdict', {}).get('overall', {}).get('malicious'),
                        'requests': len(data.get('data', {}).get('requests', [])),
                        'dom': len(data.get('data', {}).get('dom', {})),
                    }
                await asyncio.sleep(3)
            except Exception:
                await asyncio.sleep(3)
        return {'status': 'timeout'}


async def check_wayback(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            'https://archive.org/wayback/available',
            params={'url': domain},
            timeout=10.0,
        )
        available = resp.json() if resp.status_code == 200 else {}

        cdx_resp = await client.get(
            'http://web.archive.org/cdx/search/cdx',
            params={'url': domain, 'output': 'json', 'limit': 100, 'fl': 'timestamp,original,statuscode'},
            timeout=10.0,
        )
        snapshots = cdx_resp.json() if cdx_resp.status_code == 200 else []

        result = {'available': False}
        closest = available.get('archived_snapshots', {}).get('closest', {})
        if closest and closest.get('available'):
            result = {
                'available': True,
                'first_seen': snapshots[1][0][:10] if len(snapshots) > 1 else None,
                'last_seen': snapshots[-1][0][:10] if len(snapshots) > 1 else None,
                'snapshot_count': max(0, len(snapshots) - 1),
                'archive_url': closest.get('url'),
            }
        return result
    except Exception as e:
        return {'available': False, 'error': str(e)[:100]}


async def investigate_domains(combined_results: list) -> list:
    if not combined_results:
        return []

    urlscan = URLScanClient()
    gambling_domains = [d for d in combined_results if d.get('analysis', {}).get('is_gambling')]
    all_domains = combined_results

    print(f"[Investigate] Mulai: {len(all_domains)} total, "
          f"{len(gambling_domains)} gambling (akan di-scan urlscan)")

    limits = httpx.Limits(max_connections=10, max_keepalive_connections=10)
    timeout = httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=5.0)

    async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
        gambling_map = {d['domain'] for d in gambling_domains}

        for idx, entry in enumerate(all_domains):
            domain = entry['domain']
            investigation = {}

            wayback = await check_wayback(domain, client)
            investigation['wayback'] = wayback

            if domain in gambling_map and urlscan.api_key:
                search_res = await urlscan.search(domain, client)
                if search_res.get('found'):
                    investigation['urlscan'] = search_res
                else:
                    scan_res = await urlscan.submit_scan(domain, client)
                    if scan_res.get('submitted'):
                        poll_res = await urlscan.poll_result(scan_res['uuid'], client)
                        investigation['urlscan'] = {**scan_res, **poll_res}
                    else:
                        investigation['urlscan'] = scan_res
            else:
                investigation['urlscan'] = {'found': False}

            entry['investigation'] = investigation

            if (idx + 1) % 20 == 0 or idx == len(all_domains) - 1:
                scanned = sum(1 for d in all_domains[:idx + 1]
                              if d.get('investigation', {}).get('urlscan', {}).get('found'))
                print(f"\r[Investigate] {idx + 1}/{len(all_domains)} | "
                      f"urlscan found: {scanned}", end='')
                sys.stdout.flush()

            if domain in gambling_map and urlscan.api_key:
                await asyncio.sleep(1.5)

    print()
    scanned = sum(1 for d in all_domains if d.get('investigation', {}).get('urlscan', {}).get('uuid'))
    wayback_ok = sum(1 for d in all_domains if d.get('investigation', {}).get('wayback', {}).get('available'))
    print(f"[Investigate] Selesai! urlscan: {scanned} hasil, wayback: {wayback_ok} snapshot")

    return all_domains
