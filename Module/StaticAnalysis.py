# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple

import requests
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from config import Config  # 같은 프로젝트의 config.py
except Exception:
    Config = None  # 외부 단독 실행 대비


class StaticAnalysisError(Exception):
    pass


# ------------------- helpers -------------------

def _norm_list(value: Any) -> List[Any]:
    """MobSF 응답의 리스트/딕셔너리/단일값을 안전하게 리스트로 변환."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        # 값이 리스트인 카테고리 딕셔너리면 병합
        if all(isinstance(v, list) for v in value.values()):
            out: List[Any] = []
            for v in value.values():
                out.extend(v)
            return out
        # 일반 딕셔너리는 키 목록
        return list(value.keys())
    return [value]


def _mask(s: Optional[str]) -> str:
    if not s:
        return ""
    if len(s) <= 6:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 6) + s[-4:]


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if (v is not None and str(v).strip() != "") else default


def _is_json_response(resp: requests.Response) -> bool:
    ctype = resp.headers.get("Content-Type", "")
    return "application/json" in ctype.lower() or resp.text.strip().startswith("{") or resp.text.strip().startswith("[")


# ------------------- main class -------------------

class StaticAnalyzer:
    """
    MobSF 정적 분석 래퍼.
      - POST /api/v1/upload
      - POST /api/v1/scan
      - POST /api/v1/report_json  (준비될 때까지 폴링 가능)
      - (선택) POST /api/v1/delete_scan
    반환 스키마에 'apk_info.*' 포함 (run.py가 우선 참조)
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 180,
        verbose: bool = False,
        aapt_path: Optional[str] = None,   # 여기서는 보관만 (폴백 메타 추출 시 사용 가능)
        keep_cache: bool = True,
        proxies: Optional[dict] = None,
        poll: bool = True,
        poll_interval: float = 2.0,
        poll_timeout: float = 120.0,
        verify_ssl: bool = True,
        user_agent: Optional[str] = None,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ):
        # ---- 설정 소스: 인자 > Config > 환경변수 ----
        cfg = Config() if (Config is not None) else None

        self.base_url = (base_url
                         or (cfg.MOBSF_URL if (cfg and hasattr(cfg, "MOBSF_URL")) else None)
                         or _env("MOBSF_URL")
                         or "").rstrip("/")
        self.api_key = (api_key
                        or (cfg.MOBSF_API_KEY if (cfg and hasattr(cfg, "MOBSF_API_KEY")) else None)
                        or _env("MOBSF_API_KEY")
                        or "").strip().strip('"').strip("'")
        self.timeout = timeout
        self.verbose = verbose
        self.aapt_path = aapt_path or (getattr(cfg, "AAPT_PATH", None) if cfg else None)
        self.keep_cache = keep_cache
        self.verify_ssl = verify_ssl if verify_ssl is not None else True
        self.user_agent = user_agent or "MobSF-StaticAnalyzer/1.0 (+requests)"
        self.poll = poll
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout

        # 프록시: 인자 > Config.proxies() > 환경변수(REQUESTS 자동 인식)
        self.proxies = proxies if proxies is not None else (cfg.proxies() if (cfg and hasattr(cfg, "proxies")) else None)

        if not self.base_url:
            raise StaticAnalysisError("MOBSF_URL이 비어 있습니다. config.py, 환경변수, 또는 인자로 설정하세요.")
        if not (self.base_url.startswith("http://") or self.base_url.startswith("https://")):
            raise StaticAnalysisError(f"MOBSF_URL이 올바른 형식이 아닙니다: {self.base_url}")

        if not self.api_key:
            raise StaticAnalysisError("MOBSF_API_KEY가 비어 있습니다. MobSF Settings → API Key 확인 후 설정하세요.")

        # ---- HTTP 세션 + 재시도 ----
        self.session: Session = requests.Session()
        headers = {
            "Authorization": f"Token {self.api_key}",
            "X-Mobsf-Api-Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        self.session.headers.update(headers)

        # 5xx, 429에 재시도; POST도 재시도(서버가 idempotent하도록 설계됨)
        retry = Retry(
            total=max_retries,
            read=max_retries,
            connect=max_retries,
            status=max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=False,  # 모든 메서드 허용
            backoff_factor=backoff_factor,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        if self.verbose:
            print(f"[*] MobSF URL: {self.base_url}")
            print(f"[*] API Key:   { _mask(self.api_key) }")
            if self.proxies:
                print(f"[*] Proxies:   {self.proxies}")

    # ------------------- HTTP helpers -------------------

    def _post(self, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)
        if self.proxies is not None:
            kwargs.setdefault("proxies", self.proxies)
        resp = self.session.post(url, **kwargs)
        return resp

    def _ensure_json(self, resp: requests.Response) -> Dict[str, Any]:
        if not _is_json_response(resp):
            text = (resp.text or "")[:400]
            raise StaticAnalysisError(f"JSON 응답이 아닙니다 (status={resp.status_code}, body[:400]={text})")
        try:
            return resp.json()
        except Exception:
            try:
                return json.loads(resp.text)
            except Exception:
                raise StaticAnalysisError("JSON 파싱 실패")

    # ------------------- MobSF endpoints -------------------

    def _upload(self, apk_path: Path) -> Dict[str, Any]:
        with open(apk_path, "rb") as f:
            files = {"file": (apk_path.name, f, "application/vnd.android.package-archive")}
            resp = self._post("/api/v1/upload", files=files)
        if not resp.ok:
            raise StaticAnalysisError(f"Upload 실패: {resp.status_code} - {(resp.text or '')[:400]}")
        return self._ensure_json(resp)

    def _scan(self, file_name: str, file_hash: str, scan_type: str = "apk") -> Dict[str, Any]:
        data = {"scan_type": scan_type, "file_name": file_name, "hash": file_hash}
        resp = self._post("/api/v1/scan", data=data)
        if not resp.ok:
            raise StaticAnalysisError(f"Scan 실패: {resp.status_code} - {(resp.text or '')[:400]}")
        return self._ensure_json(resp)

    def _report_json_once(self, file_hash: str, scan_type: str = "apk") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """한 번 요청. (데이터, 진행상태/오류문구) 반환."""
        resp = self._post("/api/v1/report_json", data={"hash": file_hash, "scan_type": scan_type})
        if resp.ok:
            data = self._ensure_json(resp)
            msg = None
            if isinstance(data, dict) and "error" in data and isinstance(data["error"], str):
                msg = data["error"]
            return data, msg
        # 202/404/406/429/5xx 등
        body = (resp.text or "")[:200]
        return None, f"HTTP {resp.status_code}: {body}"

    def _report_json(self, file_hash: str, scan_type: str = "apk") -> Dict[str, Any]:
        """
        보고서가 아직 준비 안 되었으면 poll 옵션에 따라 재시도.
        - MobSF 변종에서 2xx + {'error': 'not complete'} 형태로 주는 케이스를 처리.
        - 429/5xx는 백오프 후 재시도.
        """
        start = time.time()
        attempt = 0
        last_note = None
        interval = max(0.2, self.poll_interval)

        while True:
            attempt += 1
            data, note = self._report_json_once(file_hash=file_hash, scan_type=scan_type)

            if data is not None:
                # 보고서가 준비되었거나, 혹은 진행중 메시지가 포함된 케이스
                if note:
                    low = note.lower()
                    if self.poll and ("not complete" in low or "in progress" in low or "processing" in low):
                        last_note = note
                    else:
                        return data
                else:
                    return data
            else:
                # data=None: HTTP 오류쪽 메시지를 note로 받음
                last_note = note or last_note

            if not self.poll:
                raise StaticAnalysisError(f"Report JSON 실패: {last_note or 'poll 비활성화'}")

            # 타임아웃 확인
            if time.time() - start > self.poll_timeout:
                raise StaticAnalysisError(f"Report JSON 준비 대기 타임아웃: {last_note or 'timeout'}")

            # 지수 백오프 + 약간의 지터
            sleep_s = min(5.0, interval * (1.5 ** max(0, attempt - 1))) + (0.05 * (attempt % 3))
            time.sleep(sleep_s)

    def _delete_scan(self, file_hash: str, scan_type: str = "apk") -> Optional[Dict[str, Any]]:
        try:
            resp = self._post("/api/v1/delete_scan", data={"hash": file_hash, "scan_type": scan_type})
            return self._ensure_json(resp) if resp.ok else None
        except Exception:
            return None

    # ------------------- Public API -------------------

    def analyze(self, apk_path: Path) -> Dict[str, Any]:
        """APK → 업로드 → 스캔 → JSON 리포트 → 표준화 결과 반환."""
        apk_path = Path(apk_path)
        if not apk_path.is_file():
            raise FileNotFoundError(f"APK 파일을 찾을 수 없습니다: {apk_path}")

        if self.verbose:
            print(f"[*] Upload: {apk_path}")

        up = self._upload(apk_path)
        fhash = up.get("hash")
        fname = up.get("file_name")
        if not fhash or not fname:
            raise StaticAnalysisError(f"Upload 응답 비정상: {up}")

        if self.verbose:
            print(f"[*] Scan: file={fname}, hash={fhash}")

        _ = self._scan(file_name=fname, file_hash=fhash, scan_type="apk")

        if self.verbose:
            print(f"[*] Report JSON: hash={fhash}")

        report = self._report_json(file_hash=fhash, scan_type="apk")

        if not self.keep_cache:
            self._delete_scan(file_hash=fhash, scan_type="apk")

        apk_info = self._extract_apk_info(report)

        result: Dict[str, Any] = {
            "apk_info": apk_info,
            "permissions": _norm_list(report.get("permissions")),
            "urls": report.get("urls") or [],
            "trackers": report.get("trackers") or {},
            "binary_analysis": report.get("binary_analysis") or {},
            "certificate_analysis": report.get("certificate_analysis") or {},
            "code_analysis": report.get("code_analysis") or {},
            "report": report,  # 원문 전체
            "_meta": {"hash": fhash, "file_name": fname},
            "source": {"base_url": self.base_url, "verify_ssl": self.verify_ssl},
        }

        if self.verbose:
            pkg = apk_info.get("package_name") or apk_info.get("package") or "(unknown)"
            main = apk_info.get("main_activity") or "(unknown)"
            print(f"[*] Done: package={pkg}, main_activity={main}")

        return result

    # ------------------- extractors -------------------

    def _extract_apk_info(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        리포트에서 apk 메타를 일관된 형태로 구성:
          - 우선 'apk_info.*'
          - 없으면 'apk_meta.*'를 매핑
          - 그래도 없으면 빈 값
        """
        apk_info = report.get("apk_info") or {}
        if not isinstance(apk_info, dict) or not apk_info:
            apk_meta = report.get("apk_meta") or {}
            if isinstance(apk_meta, dict) and apk_meta:
                apk_info = {
                    "package_name": apk_meta.get("package") or apk_meta.get("package_name"),
                    "main_activity": apk_meta.get("main_activity"),
                    "version_name": apk_meta.get("version_name"),
                    "min_sdk": apk_meta.get("min_sdk"),
                    "target_sdk": apk_meta.get("target_sdk"),
                }
            else:
                apk_info = {}

        apk_info.setdefault("package_name", None)
        apk_info.setdefault("main_activity", None)
        apk_info.setdefault("version_name", None)
        apk_info.setdefault("min_sdk", None)
        apk_info.setdefault("target_sdk", None)
        return apk_info


# ---- 모듈 단독 테스트 (선택) ----
if __name__ == "__main__":
    # 환경변수 또는 config.py에서 MOBSF_URL / MOBSF_API_KEY가 셋업되어 있어야 합니다.
    sa = StaticAnalyzer(verbose=True, keep_cache=True, poll_timeout=180)
    # 샘플 APK 경로 수정
    apk = Path(r"C:\Users\Public\sample.apk")
    res = sa.analyze(apk)
    print(json.dumps({
        "apk_info": res.get("apk_info"),
        "permissions_top5": _norm_list(res.get("permissions"))[:5],
        "_meta": res.get("_meta"),
        "source": res.get("source"),
    }, ensure_ascii=False, indent=2))
