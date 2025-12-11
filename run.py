from __future__ import annotations

import argparse
import sys
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

# ---- TZ: Asia/Seoul ----
try:
    from zoneinfo import ZoneInfo

    KST = ZoneInfo("Asia/Seoul")
except Exception:
    KST = None  # tzdata 미설치 환경 대비, 표시만 로컬로

# -----------------------------
# Config: 외부 config.py 있으면 우선 사용
# -----------------------------
try:
    # 사용자가 별도 config.py를 둘 수 있음 (Config 클래스 기반)
    from config import Config as _ExternalConfig  # type: ignore

    ExternalConfigAvailable = True
except Exception:
    ExternalConfigAvailable = False
    _ExternalConfig = None  # type: ignore


class Config:
    """
    기본값(내장). 외부 config.py가 있으면 그것이 기본값이 되고,
    CLI 인자는 최종적으로 모든 설정을 덮어씁니다.
    """

    # 공통
    VERBOSE: bool = False
    DEVICE: str = "emulator-5554"

    # 경로
    ROOT_DIR: Path = Path(__file__).resolve().parent
    LOG_DIR: Path = ROOT_DIR / "Log"
    RESULT_DIR: Path = ROOT_DIR / "Result"

    # MobSF (정적/동적)
    MOBSF_URL: Optional[str] = None
    MOBSF_API_KEY: Optional[str] = None

    # ADB (Module/ADBController에서 자동 탐지하므로 일반적으로 필요 없음)
    ADB_PATH: Optional[str] = None

    # 동적 분석
    USE_FRIDA: bool = False
    FRIDA_SCRIPT: Optional[Path] = None
    DYNAMIC_INTERACTION_SEC: int = 60
    DYNAMIC_CLEANUP: bool = False  # 동적 종료 후 MobSF 스캔 삭제

    # Static Analyzer 보조
    AAPT_PATH: Optional[str] = None
    KEEP_CACHE: bool = True  # MobSF 캐시 유지 (delete_scan 수행하지 않음)


def now_kst_iso() -> str:
    dt = datetime.now().astimezone(KST) if KST else datetime.now()
    return dt.isoformat(timespec="seconds")


# -----------------------------
# Logging
# -----------------------------
def setup_logging(log_dir: Path, verbose: bool) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("runner")
    logger.setLevel(logging.INFO)
    if logger.hasHandlers():
        logger.handlers.clear()

    fh = logging.FileHandler(
        log_dir / f"run_{datetime.now().strftime('%Y%m%d')}.log",
        mode="a",
        encoding="utf-8",
    )
    fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(fh)

    if verbose:
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logger.addHandler(ch)

    return logger


# -----------------------------
# AAPT로 패키지명 폴백
# -----------------------------
def _package_from_aapt(apk_path: Path, aapt_path: Optional[str]) -> Optional[str]:
    """
    aapt dump badging 출력에서 package name 추출
    - aapt_path가 주어지면 그 바이너리를 우선 사용
    - 없으면 PATH 상의 aapt 시도
    """
    candidates = []
    if aapt_path:
        candidates.append(aapt_path)
    candidates.append("aapt")

    for aapt in candidates:
        try:
            cp = subprocess.run(
                [aapt, "dump", "badging", str(apk_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if cp.returncode == 0 and "package: name='" in (cp.stdout or ""):
                for line in cp.stdout.splitlines():
                    if line.startswith("package: name="):
                        return line.split("package: name='", 1)[1].split("'", 1)[0]
        except Exception:
            continue
    return None


# -----------------------------
# EncDec 자동 리포트 (별도 HTML)
# -----------------------------


def generate_encdec_report(
    apk_path: Path, dynamic_result: dict, result_dir: Path
) -> Optional[Path]:
    """
    EncDec 모듈의 심볼을 유연하게 탐색하고, 렌더러가 없으면 최소 HTML을 직접 생성.
    """
    try:
        import Module.EncDec as encdec
    except Exception as e:
        print(f"[EncDec] 모듈 임포트 실패: {e}")
        return None

    import zipfile
    import types

    def _call_with_instance_fallback(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except TypeError:
            # 클래스 내부 정의라 self가 누락된 경우 → EncDecAnalyzer 인스턴스 생성 후 동일 메서드명으로 호출
            EncCls = getattr(encdec, "EncDecAnalyzer", None)
            if EncCls:
                try:
                    inst = EncCls()
                    bound = getattr(inst, getattr(fn, "__name__", ""))
                    if callable(bound):
                        return bound(*args, **kwargs)
                except Exception:
                    pass
            raise

    def _read_jsonl(jsonl_path: Path):
        if not jsonl_path or not jsonl_path.exists():
            return []
        out = []
        for line in jsonl_path.read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                pass
        return out

    def _resolve_callable(module: types.ModuleType, names: list[str]):
        for nm in names:
            fn = getattr(module, nm, None)
            if callable(fn):
                return fn
            for cls_name in ("EncDecAnalyzer", "Analyzer", "EncDec", "EncAnalyzer"):
                cls = getattr(module, cls_name, None)
                if cls:
                    cand = getattr(cls, nm, None)
                    if callable(cand):
                        return cand
        return None

    # 공개 심볼 덤프(디버그 참고)
    try:
        public_syms = [k for k in dir(encdec) if not k.startswith("_")]
        print(f"[EncDec] 공개 심볼: {', '.join(public_syms[:80])} ...")
    except Exception:
        pass

    analyze_fn = _resolve_callable(
        encdec, ["analyze_apk_for_dex", "analyze_dex", "analyze"]
    )
    decrypt_fn = _resolve_callable(
        encdec, ["try_decrypt_suspects", "decrypt_suspects", "try_decrypt"]
    )
    render_fn = _resolve_callable(
        encdec, ["render_html", "render", "render_report_html"]
    )

    if not analyze_fn:
        print(
            "[EncDec] analyze 함수 심볼을 찾지 못했습니다. EncDec.py 내 함수/클래스 이름을 확인하세요."
        )
        return None

    apk_path = Path(apk_path)
    apk_stem = apk_path.stem
    enc_dir = result_dir / f"{apk_stem}_encdec"
    enc_dir.mkdir(parents=True, exist_ok=True)

    # 1) DEX 상태 스캔
    try:
        enc_result = _call_with_instance_fallback(analyze_fn, apk_path)  # dict 기대
    except Exception as e:
        print(f"[EncDec] analyze 실행 실패: {e}")
        return None

    # 2) suspect dex 임시 추출
    suspects = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for f in enc_result.get("files", []):
                name = f.get("name") or ""
                if not name.lower().endswith(".dex"):
                    continue
                if f.get("magic_ok") is True:
                    continue
                try:
                    data = z.read(name)
                    tmp = enc_dir / (Path(name).name.replace("/", "_") + ".sus")
                    tmp.write_bytes(data)
                    suspects.append(tmp)
                except Exception:
                    pass
    except Exception:
        pass

    # 3) Frida 이벤트 JSONL 경로 탐색
    events_jsonl = None
    fr_meta = dynamic_result.get("_frida") or {}
    if isinstance(fr_meta, dict) and fr_meta.get("log"):
        p = Path(fr_meta["log"])
        if p.exists():
            events_jsonl = p
    if not events_jsonl:
        log_dir_guess = result_dir.parent / "Log"
        if log_dir_guess.exists():
            cands = sorted(log_dir_guess.glob(f"*{apk_stem}*frida*.jsonl"))
            if cands:
                events_jsonl = cands[0]

    events = _read_jsonl(events_jsonl) if events_jsonl else []

    # 4) 복호화 시도(있을 때만)
    if decrypt_fn and suspects:
        try:
            decrypt_fn and suspects and _call_with_instance_fallback(
                decrypt_fn,
                suspects=suspects,
                events_jsonl=(events_jsonl or Path("")),
                out_dir=enc_dir,
            )
        except Exception:
            pass

    # 5) HTML 생성
    out_html = result_dir / f"{apk_stem}_encdec.html"
    if render_fn:
        try:
            try:
                html = _call_with_instance_fallback(
                    render_fn, enc_result=enc_result, events=events
                )
            except TypeError:
                html = _call_with_instance_fallback(render_fn, enc_result, events)
            out_html.write_text(html, encoding="utf-8")
            return out_html
        except Exception as e:
            print(f"[EncDec] render 함수 실행 실패, 최소 HTML로 대체: {e}")

    # (폴백) 최소 HTML: JSON 임베드
    fallback = {
        "apk": str(apk_path),
        "enc_result": enc_result,
        "events": events[-200:],  # 최근 200줄
    }
    html_min = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Enc/Frida Report (fallback)</title>
<style>body{{font-family:Segoe UI,Roboto,Arial,sans-serif;margin:24px}}pre{{white-space:pre-wrap;word-break:break-all;background:#f7f7f7;padding:12px;border:1px solid #eee;border-radius:6px}}</style>
</head><body>
<h2>Enc/Frida Report (fallback)</h2>
<p>렌더러가 없어 최소 보고서를 생성했습니다.</p>
<h3>요약</h3>
<ul>
  <li>DEX 총: {enc_result.get('summary',{}).get('dex_total',0)}</li>
  <li>정상: {enc_result.get('summary',{}).get('dex_magic_ok',0)}</li>
  <li>의심: {enc_result.get('summary',{}).get('dex_suspect',0)}</li>
</ul>
<h3>원자료(JSON)</h3>
<pre id="data"></pre>
<script>document.getElementById('data').textContent = {json.dumps(fallback, ensure_ascii=False)};</script>
</body></html>"""
    out_html.write_text(html_min, encoding="utf-8")
    return out_html


# -----------------------------
# 메인 실행
# -----------------------------
def main(argv: Optional[list[str]] = None) -> int:
    # 1) 외부 Config → 내부 기본 Config → CLI override 순으로 병합
    cfg = Config()
    if ExternalConfigAvailable:
        try:
            ext = _ExternalConfig()  # type: ignore
            # 외부 설정이 있으면 우선 채택
            for k, v in ext.__dict__.items():
                if k.isupper():
                    setattr(cfg, k, v)
        except Exception:
            pass

    # 2) CLI 옵션
    p = argparse.ArgumentParser(
        description="MobSF/APK 정적·동적 분석 실행기",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("apk", type=str, help="분석 대상 APK 경로")
    p.add_argument("--device", type=str, default=cfg.DEVICE, help="ADB 디바이스 ID(-s)")
    p.add_argument(
        "--verbose", action="store_true", default=cfg.VERBOSE, help="상세 로그 출력"
    )
    p.add_argument(
        "--log-dir", type=str, default=str(cfg.LOG_DIR), help="로그 디렉터리"
    )
    p.add_argument(
        "--result-dir", type=str, default=str(cfg.RESULT_DIR), help="결과 디렉터리"
    )

    # MobSF (정적/동적 공통)
    p.add_argument(
        "--mobsf-url",
        type=str,
        default=(cfg.MOBSF_URL or ""),
        help="MobSF 서버 URL (예: http://127.0.0.1:8000)",
    )
    p.add_argument(
        "--mobsf-api-key",
        type=str,
        default=(cfg.MOBSF_API_KEY or ""),
        help="MobSF API Key",
    )

    # Static 보조
    p.add_argument(
        "--aapt-path", type=str, default=(cfg.AAPT_PATH or ""), help="aapt 경로(선택)"
    )
    p.add_argument(
        "--keep-cache",
        action="store_true",
        default=cfg.KEEP_CACHE,
        help="MobSF 캐시 유지(delete_scan 생략)",
    )

    # Dynamic
    p.add_argument(
        "--use-frida",
        action="store_true",
        default=cfg.USE_FRIDA,
        help="Frida 스크립트 사용",
    )
    p.add_argument(
        "--frida-script",
        type=str,
        default=(str(cfg.FRIDA_SCRIPT) if cfg.FRIDA_SCRIPT else ""),
        help="Frida 스크립트 경로(.js)",
    )
    p.add_argument(
        "--interaction-sec",
        type=int,
        default=cfg.DYNAMIC_INTERACTION_SEC,
        help="Monkey 상호작용 시간(초)",
    )
    p.add_argument(
        "--cleanup-scan",
        action="store_true",
        default=cfg.DYNAMIC_CLEANUP,
        help="동적 분석 후 MobSF 스캔 삭제",
    )

    args = p.parse_args(argv)

    # 3) CLI → cfg 덮어쓰기
    cfg.VERBOSE = bool(args.verbose)
    cfg.DEVICE = args.device
    cfg.LOG_DIR = Path(args.log_dir)
    cfg.RESULT_DIR = Path(args.result_dir)
    cfg.MOBSF_URL = args.mobsf_url or None
    cfg.MOBSF_API_KEY = args.mobsf_api_key or None
    cfg.AAPT_PATH = args.aapt_path or None
    cfg.KEEP_CACHE = bool(args.keep_cache)
    cfg.USE_FRIDA = bool(args.use_frida)
    cfg.FRIDA_SCRIPT = Path(args.frida_script) if args.frida_script else None
    cfg.DYNAMIC_INTERACTION_SEC = int(args.interaction_sec)
    cfg.DYNAMIC_CLEANUP = bool(args.cleanup_scan)

    logger = setup_logging(cfg.LOG_DIR, cfg.VERBOSE)
    logger.info("=== run.py 시작 (%s) ===", now_kst_iso())

    apk_path = Path(args.apk).resolve()
    if not apk_path.exists():
        logger.error("APK 파일이 존재하지 않습니다: %s", apk_path)
        return 2

    # 4) Static 분석
    from Module.StaticAnalysis import StaticAnalyzer  # type: ignore

    try:
        sa = StaticAnalyzer(
            base_url=cfg.MOBSF_URL,
            api_key=cfg.MOBSF_API_KEY,
            verbose=cfg.VERBOSE,
            aapt_path=cfg.AAPT_PATH,
            keep_cache=cfg.KEEP_CACHE,
        )
    except Exception as e:
        logger.error("StaticAnalyzer 초기화 실패: %s", e)
        return 3

    try:
        sres: Dict[str, Any] = sa.analyze(apk_path)
    except Exception as e:
        logger.error("정적 분석 실패: %s", e, exc_info=cfg.VERBOSE)
        return 4

    apk_info = sres.get("apk_info") or {}
    package = apk_info.get("package_name") or apk_info.get("package")
    logger.info(
        "정적 분석 완료: package=%s, version=%s", package, apk_info.get("version_name")
    )

    # ✅ AAPT 폴백 (패키지명 미검출 시)
    if not package:
        # 1) Module.FridaAdditional.get_package_name_via_aapt 시도
        try:
            from Module.FridaAdditional import get_package_name_via_aapt  # type: ignore

            pkg = None
            if cfg.AAPT_PATH:
                # FridaAdditional가 고정 'aapt'를 쓰므로, 직접 aapt 실행도 병행
                pkg = _package_from_aapt(apk_path, cfg.AAPT_PATH)
            if not pkg:
                pkg = get_package_name_via_aapt(apk_path)
            if not pkg:
                # 최종 시도: PATH 내 aapt
                pkg = _package_from_aapt(apk_path, None)
        except Exception:
            pkg = _package_from_aapt(apk_path, cfg.AAPT_PATH) or _package_from_aapt(
                apk_path, None
            )

        if pkg:
            package = pkg
            apk_info["package_name"] = package
            sres["apk_info"] = apk_info
            logger.info("AAPT 폴백 성공: package=%s", package)
        else:
            logger.error("패키지명을 알 수 없어 동적 분석을 제한합니다.")

    # 5) Dynamic 분석
    try:
        from Module.DynamicAnalysis import DynamicAnalyzer  # type: ignore
    except ImportError as e:
        logger.warning("DynamicAnalysis 모듈 임포트 실패: %s", e)
        DynamicAnalyzer = None

    dres: Dict[str, Any] = {}
    if not package:
        logger.warning("패키지명이 없어 동적 분석을 생략합니다.")
    elif DynamicAnalyzer is None:
        logger.warning("DynamicAnalysis 클래스를 불러오지 못해 동적 분석을 생략합니다.")
    else:
        try:
            dyn = DynamicAnalyzer(
                device=cfg.DEVICE,
                use_frida=cfg.USE_FRIDA,
                verbose=cfg.VERBOSE,
                mobsf_url=cfg.MOBSF_URL,
                mobsf_api_key=cfg.MOBSF_API_KEY,
                frida_script_path=cfg.FRIDA_SCRIPT,
                log_dir=cfg.LOG_DIR,
                result_dir=cfg.RESULT_DIR,
                interaction_duration=cfg.DYNAMIC_INTERACTION_SEC,
                cleanup_scan=cfg.DYNAMIC_CLEANUP,
            )
            dres = dyn.analyze(
                apk_path=apk_path, package_name=package, static_meta=sres
            )
        except Exception as e:
            logger.error("동적 분석 실패: %s", e, exc_info=cfg.VERBOSE)
            dres = {}

    # 6) Report (정적/동적/Frida 로그 → 단일 HTML)
    try:
        from Module.ReportResult import ReportComposer  # type: ignore

        apk_stem = apk_path.stem
        composer = ReportComposer(
            result_dir=cfg.RESULT_DIR, apk_stem=apk_stem, verbose=cfg.VERBOSE
        )
        rep = composer.generate(static_result=sres, dynamic_result=dres)
        logger.info("리포트 생성(HTML): %s", rep.get("html"))
    except Exception as e:
        logger.error("Report 생성 실패: %s", e, exc_info=cfg.VERBOSE)

    # 7) EncDec(암/복호화/DEX) 별도 HTML 자동 생성
    try:
        enc_html = generate_encdec_report(
            apk_path=apk_path, dynamic_result=dres, result_dir=cfg.RESULT_DIR
        )
        if enc_html:
            logger.info("EncDec 리포트 생성: %s", enc_html)
    except Exception as e:
        logger.warning("EncDec 리포트 생성 실패: %s", e, exc_info=cfg.VERBOSE)

    logger.info("=== run.py 종료 (%s) ===", now_kst_iso())
    return 0


if __name__ == "__main__":
    sys.exit(main())
