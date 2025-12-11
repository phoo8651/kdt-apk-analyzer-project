# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import requests

from Module.ADBController import ADBController

try:
    # 선택: 환경값 주입
    from config import Config
except Exception:
    Config = None

# (선택) Frida 로컬 주입 시 사용할 헬퍼
try:
    from Module.FridaAdditional import FridaHelper
except Exception:
    FridaHelper = None  # 없으면 로컬 프리다 생략


d_logger = logging.getLogger("DynamicAnalyzer")
d_logger.setLevel(logging.INFO)


class DynamicAnalyzer:
    """
    동적 분석 오케스트레이터
    - MobSF 관리형 모드(mobsf_url+api_key 제공 시) 또는
      로컬 주도형 모드(ADB + Frida)로 동작
    - run.py와의 호환: analyze(apk_path, package_name, static_meta?) -> Dict
    """

    def __init__(
        self,
        device: str = "emulator-5554",
        use_frida: bool = False,
        verbose: bool = False,
        mobsf_url: Optional[str] = None,
        mobsf_api_key: Optional[str] = None,
        frida_script_path: Optional[Union[str, Path]] = None,
        log_dir: Optional[Path] = None,
        result_dir: Optional[Path] = None,
        interaction_duration: int = 60,
        cleanup_scan: bool = False,
    ):
        cfg = Config() if (Config is not None) else None

        self.device_id = device or (cfg.DEVICE if cfg else "emulator-5554")
        self.use_frida = bool(use_frida)
        self.verbose = bool(verbose)

        # MobSF 동적 분석 옵션(없으면 로컬 모드)
        self.mobsf_url = (mobsf_url or (cfg.MOBSF_URL if cfg else None) or "").rstrip(
            "/"
        ) or None
        self.mobsf_api_key = (
            mobsf_api_key or (cfg.MOBSF_API_KEY if cfg else None) or ""
        ).strip() or None

        # 경로/폴더
        self.log_dir = log_dir or (cfg.LOG_DIR if cfg else Path("Log"))
        self.result_dir = result_dir or (cfg.RESULT_DIR if cfg else Path("Result"))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.result_dir.mkdir(parents=True, exist_ok=True)

        # 프리다 스크립트 (선택)
        self.frida_script_path = Path(frida_script_path) if frida_script_path else None
        if (
            self.use_frida
            and self.frida_script_path
            and not self.frida_script_path.exists()
        ):
            d_logger.warning(
                f"[Frida] 스크립트 파일을 찾을 수 없습니다: {self.frida_script_path}"
            )
            self.frida_script_path = None

        self.interaction_duration = int(interaction_duration)
        self.cleanup_scan = bool(cleanup_scan)

        # ADB 컨트롤러
        self.adb = ADBController(
            device_id=self.device_id, log_dir=self.log_dir, verbose=self.verbose
        )

        # MobSF 세션
        self.session: Optional[requests.Session] = None
        if self.mobsf_url and self.mobsf_api_key:
            self.session = requests.Session()
            # MobSF는 Authorization: Token... 또는 Authorization: <key> 유형이 혼재할 수 있어
            # Static 측과 맞추어 기본/백워드 호환 헤더 동시 세팅
            self.session.headers.update(
                {
                    "Authorization": self.mobsf_api_key,
                    "X-Mobsf-Api-Key": self.mobsf_api_key,
                    "Accept": "application/json",
                }
            )

        # 로거 핸들러 (파일 + verbose 시 콘솔)
        if d_logger.hasHandlers():
            d_logger.handlers.clear()
        fh = logging.FileHandler(
            self.log_dir / "dynamic.log", mode="a", encoding="utf-8"
        )
        fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        d_logger.addHandler(fh)
        if self.verbose:
            ch = logging.StreamHandler()
            ch.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            d_logger.addHandler(ch)

    # =========================================================
    # 공용 유틸
    # =========================================================

    @property
    def is_mobsf_mode(self) -> bool:
        return bool(self.session and self.mobsf_url and self.mobsf_api_key)

    def _mrequest(
        self, method: str, endpoint: str, max_retries: int = 3, **kwargs
    ) -> Optional[Dict[str, Any]]:
        """MobSF API 호출(재시도 포함). is_mobsf_mode가 아닌 경우 None."""
        if not self.is_mobsf_mode:
            return None
        url = f"{self.mobsf_url}{endpoint}"
        for attempt in range(1, max_retries + 1):
            try:
                r = self.session.request(method, url, timeout=120, **kwargs)  # type: ignore[arg-type]
                r.raise_for_status()
                return r.json() if r.content else {"status": "success"}
            except requests.RequestException as e:
                d_logger.warning(
                    "MobSF API 실패 %s (%d/%d): %s | %s",
                    endpoint,
                    attempt,
                    max_retries,
                    type(e).__name__,
                    e,
                )
                if attempt < max_retries:
                    time.sleep(4)
        d_logger.error("MobSF API 최대 재시도 초과: %s", endpoint)
        return None

    @staticmethod
    def _parse_components(components: Any) -> List[str]:
        """리스트 또는 문자열('a,b' 또는 '["a","b"]')을 표준 리스트로."""
        if isinstance(components, list):
            return [str(x).strip() for x in components if str(x).strip()]
        if isinstance(components, str):
            s = components.strip()
            if not s:
                return []
            # JSON/파이썬리스트 형태 시도
            if s.startswith("[") and s.endswith("]"):
                try:
                    arr = json.loads(s)
                    if isinstance(arr, list):
                        return [str(x).strip() for x in arr if str(x).strip()]
                except Exception:
                    pass
            # 콤마 구분
            return [x.strip() for x in s.split(",") if x.strip()]
        return []

    # =========================================================
    # 로컬 주도형 모드(ADB + Frida)
    # =========================================================

    def _local_run(
        self, apk_path: Path, package_name: str, exported: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        MobSF를 쓰지 않는 로컬 모드:
        - (선택) logcat 캡처
        - (선택) Frida 스크립트 주입 (FridaHelper가 있을 때)
        - Exported 컴포넌트 실행 + 스크린샷
        - Monkey 상호작용
        """
        d_logger.info("[LOCAL] 동적 분석 시작")

        # 장비/부팅 대기
        if not self.adb.wait_for_device(60):
            d_logger.error("[LOCAL] 기기 연결 대기 실패")
            return {}
        _ = self.adb.wait_boot_completed(120)

        # logcat 캡처 시작
        logcat_path = self.log_dir / f"{package_name}_logcat.txt"
        self.adb.logcat_start(logcat_path, clear_first=True, filterspec=["*:I"])

        # (선택) 프리다 주입: FridaHelper가 존재하고 스크립트가 있을 때
        frida_meta: Optional[Dict[str, Any]] = None
        if self.use_frida and self.frida_script_path and FridaHelper is not None:
            try:
                fr = FridaHelper(device=self.device_id, verbose=self.verbose)
                fr.prepare()
                # 앱 실행(없으면 spawn이 실행)
                frida_log = self.log_dir / f"{package_name}_frida.jsonl"
                frida_meta = fr.run_frida(
                    package=package_name,
                    script_path=self.frida_script_path,
                    jsonl_out=frida_log,
                    mode="spawn",
                    seconds=max(10, min(self.interaction_duration, 60)),
                    runtime="v8",
                )
                d_logger.info("[LOCAL] Frida 실행: %s", frida_meta)
            except Exception as e:
                d_logger.warning("[LOCAL] Frida 실행 실패: %s: %s", type(e).__name__, e)

        # Exported 컴포넌트 자동 시험
        screenshots = self._exercise_exported(package_name, exported)

        # Monkey 상호작용
        self.adb.run_monkey_test(package_name, duration=self.interaction_duration)

        # 정리
        self.adb.logcat_stop()

        # 결과 요약
        result = {
            "summary": f"[LOCAL] device={self.device_id}, frida={'on' if (self.use_frida and self.frida_script_path) else 'off'}",
            "runtime_logs": [str(logcat_path)] if logcat_path.exists() else [],
            "events": [],  # 로컬 모드에서는 별도 이벤트 수집 포맷이 없으므로 빈 배열(Frida JSONL은 파일 경로로 확인)
        }
        if frida_meta:
            result["_frida"] = frida_meta
        if screenshots:
            result["_screenshots"] = [str(p) for p in screenshots]
        return result

    def _exercise_exported(
        self, package_name: str, exported: Dict[str, Any]
    ) -> List[Path]:
        """
        Exported Activities/Services/Receivers를 호출하고 스크린샷 저장
        """
        act_list = self._parse_components(exported.get("exported_activities", []))
        svc_list = self._parse_components(exported.get("exported_services", []))
        rcv_list = self._parse_components(exported.get("exported_receivers", []))

        screenshot_dir = self.result_dir / f"{package_name}_screens"
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        shots: List[Path] = []

        # Activities
        for i, activity in enumerate(act_list):
            comp = f"{package_name}/{activity}"
            d_logger.info("[LOCAL] start Activity: %s", comp)
            self.adb.start_activity(comp)
            time.sleep(4)
            img = screenshot_dir / f"activity_{i}_{Path(activity).stem}.png"
            if self.adb.take_screenshot(img):
                shots.append(img)

        # Services
        for service in svc_list:
            comp = f"{package_name}/{service}"
            d_logger.info("[LOCAL] start Service: %s", comp)
            self.adb.start_service(comp)
            time.sleep(2)

        # Receivers
        for recv in rcv_list:
            action = f"{package_name}/{recv}"
            d_logger.info("[LOCAL] send Broadcast: %s", action)
            self.adb.send_broadcast(action)
            time.sleep(2)

        return shots

    # =========================================================
    # MobSF 관리형 모드
    # =========================================================

    def _mobsf_prepare(self) -> bool:
        """MobSF 환경 준비: mobsfy 연결, CA 설치, 글로벌 프록시 set."""
        d_logger.info("[MobSF] 환경 준비")
        if not self._mrequest(
            "POST", "/api/v1/android/mobsfy", data={"identifier": self.device_id}
        ):
            return False
        if not self._mrequest(
            "POST", "/api/v1/android/root_ca", data={"action": "install"}
        ):
            return False
        if not self._mrequest(
            "POST", "/api/v1/android/global_proxy", data={"action": "set"}
        ):
            return False
        time.sleep(5)
        return True

    def _mobsf_start(self, scan_hash: str) -> bool:
        r = self._mrequest(
            "POST", "/api/v1/dynamic/start_analysis", data={"hash": scan_hash}
        )
        return bool(r)

    def _mobsf_stop_and_reports(self, scan_hash: str, apk_stem: str) -> Dict[str, Any]:
        """MobSF 동적 보고서 생성 + 병렬 다운로드(JSON, PDF)"""
        self._mrequest(
            "POST", "/api/v1/dynamic/stop_analysis", data={"hash": scan_hash}
        )
        d_logger.info("[MobSF] 리포트 생성 대기 15초")
        time.sleep(15)

        out: Dict[str, Any] = {}

        def download_json():
            data = self._mrequest(
                "POST", "/api/v1/dynamic/report_json", data={"hash": scan_hash}
            )
            if data:
                p = self.result_dir / f"{apk_stem}_dynamic_report.json"
                p.write_text(
                    json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                out["json"] = str(p)
                d_logger.info("[MobSF] JSON 보고서: %s", p)

        def download_pdf():
            try:
                url = f"{self.mobsf_url}/api/v1/download_pdf"
                r = self.session.post(url, data={"hash": scan_hash}, stream=True)  # type: ignore
                r.raise_for_status()
                p = self.result_dir / f"{apk_stem}_dynamic_report.pdf"
                with open(p, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                out["pdf"] = str(p)
                d_logger.info("[MobSF] PDF 보고서: %s", p)
            except requests.RequestException as e:
                d_logger.error("[MobSF] PDF 다운로드 실패: %s", e)

        with ThreadPoolExecutor(max_workers=2) as ex:
            ex.submit(download_json)
            ex.submit(download_pdf)

        return out

    def _mobsf_cleanup(self, scan_hash: Optional[str]) -> None:
        """MobSF 설정 원복 및 (옵션) 스캔 삭제"""
        try:
            self._mrequest(
                "POST", "/api/v1/android/global_proxy", data={"action": "unset"}
            )
            self._mrequest("POST", "/api/v1/android/root_ca", data={"action": "remove"})
            if self.cleanup_scan and scan_hash:
                d_logger.info("[MobSF] 스캔 기록 삭제")
                self._mrequest("POST", "/api/v1/delete_scan", data={"hash": scan_hash})
        except Exception as e:
            d_logger.warning("[MobSF] 정리 중 오류: %s", e)

    # =========================================================
    # 퍼블릭 엔트리포인트
    # =========================================================

    def analyze(
        self,
        apk_path: Union[str, Path],
        package_name: Optional[str] = None,
        static_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        run.py와 호환되는 메인 진입점.
        - apk_path: APK 경로
        - package_name: 패키지명(없으면 static_meta에서 추출 시도)
        - static_meta: 정적 분석 결과(permissions, exported_* 등)
        반환: Reporter가 소비 가능한 dict
        """
        apk_path = Path(apk_path)
        apk_stem = apk_path.stem

        # 패키지명 확보
        if not package_name and static_meta:
            am = static_meta.get("apk_info") or static_meta.get("apk_meta") or {}
            package_name = am.get("package_name") or am.get("package")

        if not package_name:
            d_logger.error("패키지명을 알 수 없어 동적 분석을 중단합니다.")
            return {}

        # Exported 목록(있으면 사용)
        exported = static_meta or {}
        if "report" in exported and isinstance(exported["report"], dict):
            # MobSF 원본 리포트에 exported_*가 있을 수 있음
            rep = exported["report"]
            exported = {
                "exported_activities": rep.get("exported_activities")
                or rep.get("activities", []),
                "exported_services": rep.get("exported_services")
                or rep.get("services", []),
                "exported_receivers": rep.get("exported_receivers")
                or rep.get("receivers", []),
            }

        result: Dict[str, Any] = {}
        scan_hash: Optional[str] = None

        try:
            # MobSF 모드여부 결정
            if self.is_mobsf_mode:
                # 정적 결과에서 hash 확보(StaticAnalyzer.analyze 결과의 _meta.hash)
                if static_meta:
                    scan_hash = (static_meta.get("_meta") or {}).get(
                        "hash"
                    ) or static_meta.get("hash")
                if not scan_hash:
                    d_logger.error(
                        "[MobSF] 정적 결과의 hash가 없어 MobSF 동적 분석을 진행할 수 없습니다. 로컬 모드로 전환합니다."
                    )
                    return self._local_run(apk_path, package_name, exported)

                d_logger.info(
                    "[MobSF] 동적 분석 시작: device=%s, pkg=%s",
                    self.device_id,
                    package_name,
                )

                # ADB 측 준비
                if not self.adb.wait_for_device(60):
                    d_logger.error("[MobSF] 기기 연결 실패")
                    return {}

                # MobSF 환경 준비
                if not self._mobsf_prepare():
                    return {}

                # (선택) Frida 커스텀 스크립트 MobSF를 통해 주입
                if self.use_frida and self.frida_script_path:
                    try:
                        code = self.frida_script_path.read_text(encoding="utf-8")
                        payload = {
                            "hash": scan_hash,
                            "frida_code": code,
                            "default_hooks": "",
                            "auxiliary_hooks": "",
                            "class_search": "",
                        }
                        ok = self._mrequest(
                            "POST", "/api/v1/frida/instrument", data=payload
                        )
                        if not ok:
                            d_logger.warning(
                                "[MobSF] Frida 커스텀 스크립트 주입 실패(무시하고 진행)"
                            )
                    except Exception as e:
                        d_logger.warning(
                            "[MobSF] Frida 스크립트 읽기 실패(무시): %s", e
                        )

                # MobSF 동적 로깅 시작
                if not self._mobsf_start(scan_hash):
                    return {}

                # 앱 구동/Exported 시험/Monkey
                shots = self._exercise_exported(package_name, exported)
                self.adb.run_monkey_test(
                    package_name, duration=self.interaction_duration
                )

                # 리포트 수집
                reports = self._mobsf_stop_and_reports(scan_hash, apk_stem)

                # MobSF 모드 결과 형태(Reporter 호환)
                result = {
                    "summary": f"[MobSF] device={self.device_id}, pkg={package_name}, frida={'on' if (self.use_frida and self.frida_script_path) else 'off'}",
                    "runtime_logs": [],  # logcat 파일 경로나 MobSF 원격 로그는 여기선 생략
                    "events": [],  # MobSF 동적 이벤트 원문은 JSON 보고서에 포함
                    "_mobsf_reports": reports,
                }
                if shots:
                    result["_screenshots"] = [str(p) for p in shots]
            else:
                # 로컬 모드
                result = self._local_run(apk_path, package_name, exported)

        except Exception as e:
            d_logger.critical("동적 분석 중 오류: %s", e, exc_info=True)
        finally:
            # MobSF 환경 정리
            if self.is_mobsf_mode:
                self._mobsf_cleanup(scan_hash)

        return result
