#!/usr/bin/env python3
"""
NVD CVE API 2.0 収集スクリプト

- 初回実行: フル取得(全CVE)
- 2回目以降: last_sync.json に記録した lastModStartDate を起点に差分取得
- 出力: ./output/nvd_cves_YYYYMMDD_HHMMSS.json (このファイルのみをオフラインホストへ持ち出す想定)

事前準備:
    export NVD_API_KEY="取得したAPIキー"

実行:
    python3 nvd_fetch.py
"""

import os
import sys
import json
import time
import requests
from datetime import datetime, timezone, timedelta

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
STATE_FILE = "last_sync.json"
OUTPUT_DIR = "output"

API_KEY = os.environ.get("NVD_API_KEY")
if not API_KEY:
    print("[警告] 環境変数 NVD_API_KEY が未設定です。無キーのレート制限(5req/30s)で実行します。", file=sys.stderr)

# キーあり: 30秒50件 -> 余裕をみて0.65秒間隔 / キーなし: 30秒5件 -> 6.5秒間隔
SLEEP_SEC = 0.65 if API_KEY else 6.5

# NVD APIの日付範囲フィルタ(lastModStartDate/EndDate等)は最大120日間の制約がある
MAX_RANGE_DAYS = 120


def _headers():
    h = {"Accept": "application/json"}
    if API_KEY:
        h["apiKey"] = API_KEY
    return h


def _request_with_retry(params, max_retries=5):
    """403/503/429時に指数バックオフしつつリクエストする"""
    delay = 5
    for attempt in range(1, max_retries + 1):
        resp = requests.get(BASE_URL, params=params, headers=_headers(), timeout=30)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (403, 429, 503):
            print(f"[再試行 {attempt}/{max_retries}] status={resp.status_code} " f"{delay}秒待機します", file=sys.stderr)
            time.sleep(delay)
            delay = min(delay * 2, 60)
            continue
        resp.raise_for_status()
    raise RuntimeError(f"リトライ上限に達しました: params={params}")


def _fetch_all(extra_params=None):
    """startIndexでページングしながら全件取得する共通処理"""
    extra_params = extra_params or {}
    all_cves = []
    start_index = 0

    while True:
        params = {
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
            **extra_params,
        }
        data = _request_with_retry(params)
        vulns = data.get("vulnerabilities", [])
        all_cves.extend(vulns)

        total_results = data.get("totalResults", 0)
        print(f"  取得中: {start_index + len(vulns)} / {total_results}")

        start_index += RESULTS_PER_PAGE
        if start_index >= total_results:
            break
        time.sleep(SLEEP_SEC)

    return all_cves


def full_fetch():
    print("[フル取得] 全CVEレコードを取得します(初回は時間がかかります)")
    return _fetch_all()


def incremental_fetch(since_iso):
    """
    since_iso: 前回同期時刻(ISO8601, UTC)
    lastModStartDate/EndDateは最大120日間の制約があるため、必要に応じて分割する
    """
    start_dt = datetime.fromisoformat(since_iso)
    end_dt = datetime.now(timezone.utc)

    all_cves = []
    window_start = start_dt

    while window_start < end_dt:
        window_end = min(window_start + timedelta(days=MAX_RANGE_DAYS), end_dt)
        print(f"[差分取得] {window_start.isoformat()} 〜 {window_end.isoformat()}")

        params = {
            "lastModStartDate": window_start.strftime("%Y-%m-%dT%H:%M:%S.000%z"),
            "lastModEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.000%z"),
        }
        all_cves.extend(_fetch_all(params))

        window_start = window_end
        time.sleep(SLEEP_SEC)

    return all_cves


def normalize(vulnerabilities):
    """必要最低限の正規化。ソース元データはcve配下にそのまま保持"""
    records = []
    for item in vulnerabilities:
        cve = item.get("cve", {})
        descriptions = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
        cvss = cvss_v31 or cvss_v30

        records.append({
            "cve_id": cve.get("id"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description_en": desc_en,
            "cvss_version": cvss.get("version"),
            "cvss_score": cvss.get("baseScore"),
            "cvss_severity": cvss.get("baseSeverity"),
            "source": "NVD",
            "raw": cve,  # 後段でCWE/CPE等を参照する場合に備え元データを保持
        })
    return records


def save_output(records):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(OUTPUT_DIR, f"nvd_cves_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    print(f"[完了] {len(records)}件を書き出しました: {path}")
    return path


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def save_state():
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"last_sync": datetime.now(timezone.utc).isoformat()}, f)


def main():
    state = load_state()

    if state is None:
        vulnerabilities = full_fetch()
    else:
        vulnerabilities = incremental_fetch(state["last_sync"])

    records = normalize(vulnerabilities)
    save_output(records)
    save_state()


if __name__ == "__main__":
    main()
