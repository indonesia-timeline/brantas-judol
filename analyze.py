#!/usr/bin/env python3
"""
Layer 4: LLM Analysis - Klasifikasi domain judi online via Gemini 2.5 Flash.
Multi-key round-robin untuk handle rate limit.
"""

import json
import os
import random
import re
import sys
import time
from typing import Optional

import google.generativeai as genai


SYSTEM_PROMPT = """Anda adalah classifier domain judi online. Analisis domain berikut dan tentukan apakah terkait judi online.

Perhatikan:
1. Judul halaman (title)
2. Meta description
3. Nama domain itu sendiri

Kategori:
- "slot": mesin slot, slot online, pragmatic, pgsoft, microgaming, slot gacor
- "casino": live casino, baccarat, roulette, blackjack, sicbo
- "poker": poker, domino, bandarq, sakong, aduq
- "sports_betting": taruhan bola, sbobet, parlay, handicap
- "lottery": togel, toto, lotre, 4d
- "trading": binary option, trading platform, forex (bukan judi tapi terkait)
- "other_gambling": jenis judi lain yang tidak termasuk di atas
- null: bukan judi sama sekali

Subkategori (hanya jika is_gambling=true):
- Nama platform/provider seperti "pragmatic_play", "pg_soft", "microgaming", "habanero", "spadegaming", "joker", "playtech", "netent", atau null

Return ONLY valid JSON array, tanpa markdown, tanpa backticks, tanpa teks lain:
[{"domain":"...","is_gambling":true/false,"category":... or null,"subcategory":... or null,"confidence":0.0-1.0,"language":"id"/"en"/"other","reasoning":"..."}]"""


class GeminiAnalyzer:
    def __init__(self):
        keys_str = os.environ.get('GEMINI_KEYS', '')
        self.keys = [k.strip() for k in keys_str.split(',') if k.strip()]
        if not self.keys:
            print("[!] GEMINI_KEYS tidak di-set. LLM analysis akan di-skip.")
            self.keys = []
        random.shuffle(self.keys)
        self.idx = 0
        self.model_name = 'models/gemini-2.5-flash'

    def _build_batch_prompt(self, batch: list) -> str:
        lines = []
        for i, d in enumerate(batch, 1):
            domain = d.get('domain', '?')
            title = d.get('title') or '-'
            desc = d.get('description') or '-'
            lines.append(f"{i}. domain: {domain}")
            lines.append(f"   title: {title}")
            if desc != '-':
                lines.append(f"   description: {desc}")
            lines.append('')
        return '\n'.join(lines)

    def _try_parse(self, text: str, expected_count: int) -> Optional[list]:
        text = text.strip()
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)
        try:
            data = json.loads(text)
            if isinstance(data, list) and len(data) == expected_count:
                return data
        except json.JSONDecodeError:
            pass
        match = re.search(r'\[\s*\{.*\}\s*\]', text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                pass
        return None

    def _call_gemini(self, prompt: str) -> Optional[str]:
        for attempt in range(len(self.keys) * 2):
            key = self.keys[self.idx % len(self.keys)]
            self.idx += 1
            try:
                genai.configure(api_key=key)
                model = genai.GenerativeModel(self.model_name)
                resp = model.generate_content(
                    [SYSTEM_PROMPT, prompt],
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.1,
                        max_output_tokens=2048,
                    )
                )
                if resp and resp.text:
                    return resp.text
            except Exception as e:
                err = str(e)
                if '429' in err or 'RESOURCE_EXHAUSTED' in err or 'quota' in err.lower():
                    wait = min(2 + random.random() * 2, 5)
                    time.sleep(wait)
                    continue
                if 'SAFETY' in err or 'BLOCKED' in err:
                    time.sleep(0.5)
                    continue
                print(f"  [!] Gemini error (key {self.idx % len(self.keys)}): {type(e).__name__}")
                time.sleep(1)
                continue
        return None

    def analyze_batch(self, batch: list) -> list:
        if not self.keys:
            return [{'domain': d['domain'], 'is_gambling': False, 'category': None,
                     'subcategory': None, 'confidence': 0.0, 'language': 'other',
                     'reasoning': 'no_api_key'} for d in batch]

        prompt = self._build_batch_prompt(batch)
        text = self._call_gemini(prompt)
        if text:
            parsed = self._try_parse(text, len(batch))
            if parsed:
                return parsed
        return [{'domain': d['domain'], 'is_gambling': False, 'category': None,
                 'subcategory': None, 'confidence': 0.0, 'language': 'other',
                 'reasoning': 'parse_failed'} for d in batch]


def analyze_domains(probe_results: list, batch_size: int = 15) -> list:
    if not probe_results:
        return []

    analyzer = GeminiAnalyzer()
    if not analyzer.keys:
        print("[Analyze] GEMINI_KEYS tidak tersedia, skip analisis LLM")
        return [{'domain': d['domain'], 'is_gambling': False, 'category': None,
                 'subcategory': None, 'confidence': 0.0, 'language': 'other',
                 'reasoning': 'no_api_key'} for d in probe_results]

    total = len(probe_results)
    print(f"[Analyze] Mulai klasifikasi {total} domain via Gemini (batch={batch_size})...")

    all_results = []
    for start in range(0, total, batch_size):
        batch = probe_results[start:start + batch_size]
        results = analyzer.analyze_batch(batch)
        all_results.extend(results)

        done = len(all_results)
        gambling = sum(1 for r in all_results if r.get('is_gambling'))
        pct = done / total * 100
        print(f"\r[Analyze] {done}/{total} ({pct:.1f}%) | gambling: {gambling}", end='')
        sys.stdout.flush()

        if start + batch_size < total:
            time.sleep(0.3)

    print()
    gambling = sum(1 for r in all_results if r.get('is_gambling'))
    print(f"[Analyze] Selesai: {gambling}/{total} terdeteksi sebagai judi online")

    merged = {}
    for r in all_results:
        merged[r.get('domain', '')] = r

    final = []
    for d in probe_results:
        dom = d['domain']
        if dom in merged:
            final.append({**d, 'analysis': {
                'is_gambling': merged[dom].get('is_gambling', False),
                'category': merged[dom].get('category'),
                'subcategory': merged[dom].get('subcategory'),
                'confidence': merged[dom].get('confidence', 0.0),
                'language': merged[dom].get('language', 'other'),
                'reasoning': merged[dom].get('reasoning', ''),
            }})
        else:
            final.append({**d, 'analysis': {
                'is_gambling': False, 'category': None, 'subcategory': None,
                'confidence': 0.0, 'language': 'other', 'reasoning': 'missing',
            }})

    return final
