# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Iterable

ra_logger = logging.getLogger("ReportAnalyzer")
ra_logger.setLevel(logging.INFO)


# -----------------------------
# Small helpers (defensive)
# -----------------------------


def _to_strings(items):
    """리스트 요소를 전부 문자열로 안전 변환.
    dict는 url/link/href/name/value 키 우선, 없으면 JSON 문자열화."""
    out = []
    if not isinstance(items, list):
        return out
    for x in items:
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, dict):
            picked = None
            for k in ("url", "link", "href", "name", "value"):
                v = x.get(k)
                if isinstance(v, str) and v.strip():
                    picked = v.strip()
                    break
            if picked is None:
                try:
                    picked = json.dumps(x, ensure_ascii=False)
                except Exception:
                    picked = str(x)
            out.append(picked)
        else:
            out.append(str(x))
    return out


def _pretty(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        try:
            # fallback: convert to str safely
            return str(obj)
        except Exception:
            return "(unprintable)"


def _safe_str(x: Any) -> str:
    try:
        return str(x)
    except Exception:
        return ""


def _coerce_list_str(raw: Any) -> List[str]:
    """
    list/tuple -> [str...]
    "a,b"      -> ["a", "b"]
    json-like  -> try json.loads
    others     -> [str(raw)]
    """
    out: List[str] = []
    if raw is None:
        return out
    if isinstance(raw, (list, tuple)):
        for v in raw:
            s = _safe_str(v).strip()
            if s:
                out.append(s)
        return out
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return out
        # try parse json list
        if (s.startswith("[") and s.endswith("]")) or (
            s.startswith("(") and s.endswith(")")
        ):
            try:
                arr = json.loads(s)
                if isinstance(arr, list):
                    for v in arr:
                        sv = _safe_str(v).strip()
                        if sv:
                            out.append(sv)
                    return out
            except Exception:
                pass
        # comma separated
        parts = [p.strip() for p in s.split(",")]
        out.extend([p for p in parts if p])
        return out
    # anything else
    s = _safe_str(raw).strip()
    if s:
        out.append(s)
    return out


def _flatten(iterable: Iterable[Any]) -> List[Any]:
    out: List[Any] = []
    for x in iterable:
        if isinstance(x, (list, tuple)):
            out.extend(_flatten(x))
        else:
            out.append(x)
    return out


def _coerce_urls(raw: Any) -> List[str]:
    """
    다양한 구조에 섞여 있는 URL/엔드포인트를 문자열 리스트로 평탄화.
    - dict에서는 url/endpoint/href/location 혹은 host + path 조합을 우선 수집
    - list/tuple은 재귀
    - 문자열 아닌 타입은 str() 변환
    - 중복 제거 + 정렬
    """
    out: List[str] = []

    def add(x: Any):
        if x is None:
            return
        if isinstance(x, str):
            s = x.strip()
            if s:
                out.append(s)
            return
        if isinstance(x, dict):
            # 우선순위 키
            for k in ("url", "endpoint", "href", "location"):
                v = x.get(k)
                if isinstance(v, str) and v.strip():
                    out.append(v.strip())
                    return
            # 조합
            host = x.get("host")
            path = x.get("path") or x.get("uri") or x.get("endpoint")
            if isinstance(host, str) and host.strip():
                if isinstance(path, str) and path.strip():
                    out.append(
                        host.strip().rstrip("/") + "/" + path.strip().lstrip("/")
                    )
                else:
                    out.append(host.strip())
                return
            # 기타 문자열성 값들을 최대 1~2개만 우회 취득(과다 노이즈 방지)
            for k, v in list(x.items())[:4]:
                if isinstance(v, str) and v.strip():
                    out.append(v.strip())
            return
        if isinstance(x, (list, tuple)):
            for i in x:
                add(i)
            return
        # 기타 타입
        s = _safe_str(x).strip()
        if s:
            out.append(s)

    add(raw)
    # normalize -> string only
    out = [u for u in out if isinstance(u, str) and u.strip()]
    # uniq preserve order
    uniq: List[str] = []
    seen = set()
    for u in out:
        if u not in seen:
            uniq.append(u)
            seen.add(u)
    # sort (length then alpha) for readability
    uniq.sort(key=lambda s: (len(s), s))
    return uniq


def _to_rel(result_dir: Path, p: Any) -> str:
    s = _safe_str(p)
    if not s:
        return s
    try:
        return str(Path(s).resolve().relative_to(result_dir.resolve()))
    except Exception:
        return s


# -----------------------------
# Composer
# -----------------------------
class ReportComposer:
    """
    통합 HTML/텍스트 리포트 생성기
    - 상단: 정적 요약 + 동적 요약
    - 중간: 링크, 네트워크 URL, 스크린샷
    - 하단: 정적/동적 원문 JSON (details)
    """

    def __init__(self, result_dir: Path, apk_stem: str, verbose: bool = False):
        self.result_dir = Path(result_dir)
        self.apk_stem = apk_stem
        self.verbose = verbose

        if ra_logger.hasHandlers():
            ra_logger.handlers.clear()
        self.result_dir.mkdir(parents=True, exist_ok=True)

        fh = logging.FileHandler(
            self.result_dir / "report.log", mode="a", encoding="utf-8"
        )
        fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        ra_logger.addHandler(fh)
        if verbose:
            ch = logging.StreamHandler()
            ch.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
            ra_logger.addHandler(ch)

    # -------------------------
    # Public API
    # -------------------------
    def generate(
        self,
        static_result: Dict[str, Any],
        dynamic_result: Dict[str, Any],
        extra_links: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        extra_links = extra_links or {}
        html = self._build_html(static_result, dynamic_result, extra_links)
        html_path = self.result_dir / f"{self.apk_stem}_report.html"
        html_path.write_text(html, encoding="utf-8")

        text = self._build_text_summary(static_result, dynamic_result)
        text_path = self.result_dir / f"{self.apk_stem}_summary_report.txt"
        text_path.write_text(text, encoding="utf-8")

        ra_logger.info("HTML 리포트 생성: %s", html_path)
        ra_logger.info("텍스트 요약 리포트 생성: %s", text_path)
        return {"html": str(html_path), "text": str(text_path)}

    # -------------------------
    # Builders
    # -------------------------
    def _build_html(
        self,
        static_result: Dict[str, Any],
        dynamic_result: Dict[str, Any],
        extra_links: Dict[str, str],
    ) -> str:
        # --- Static info ---
        apk_meta = static_result.get("apk_info") or static_result.get("apk_meta") or {}
        app_name = apk_meta.get("app_name") or self.apk_stem
        package = apk_meta.get("package_name") or apk_meta.get("package") or "N/A"
        version = apk_meta.get("version_name") or apk_meta.get("version") or "N/A"
        md5 = (
            apk_meta.get("md5")
            or static_result.get("hash")
            or (static_result.get("_meta") or {}).get("md5")
            or "N/A"
        )
        target_sdk = apk_meta.get("target_sdk") or "N/A"

        exported_acts = _coerce_list_str(
            (static_result.get("report") or {}).get("exported_activities")
        )
        exported_svcs = _coerce_list_str(
            (static_result.get("report") or {}).get("exported_services")
        )
        exported_rcvs = _coerce_list_str(
            (static_result.get("report") or {}).get("exported_receivers")
        )
        permissions = _coerce_list_str(
            (static_result.get("report") or {}).get("permissions")
        )

        # --- Dynamic info ---
        dyn_summary = _safe_str(dynamic_result.get("summary") or "")
        screenshots_raw = dynamic_result.get("_screenshots") or []
        screenshots = [s for s in _coerce_list_str(screenshots_raw) if s]

        frida_meta = dynamic_result.get("_frida") or {}
        mobsf_reports = dynamic_result.get("_mobsf_reports") or {}

        # --- URLs (defensive) ---
        urls_candidate = (
            dynamic_result.get("urls") or dynamic_result.get("network") or []
        )
        urls = _coerce_urls(urls_candidate)

        # --- Links (defensive) ---
        link_lines: List[str] = []
        json_report = mobsf_reports.get("json")
        pdf_report = mobsf_reports.get("pdf")
        if isinstance(json_report, str) and json_report.strip():
            link_lines.append(
                f'<a href="{_to_rel(self.result_dir, json_report)}" target="_blank">동적 JSON 보고서</a>'
            )
        if isinstance(pdf_report, str) and pdf_report.strip():
            link_lines.append(
                f'<a href="{_to_rel(self.result_dir, pdf_report)}" target="_blank">동적 PDF 보고서</a>'
            )
        # extra links
        for k, v in extra_links.items():
            ks = _safe_str(k).strip() or "Link"
            vs = _safe_str(v).strip()
            if vs:
                link_lines.append(
                    f'<a href="{_to_rel(self.result_dir, vs)}" target="_blank">{ks}</a>'
                )
        links_html = (
            "<br>".join(link_lines)
            if link_lines
            else '<small class="muted">첨부 링크 없음</small>'
        )

        # --- Screenshots ---
        if screenshots:
            shot_cells = []
            for p in screenshots[:40]:
                rp = _to_rel(self.result_dir, p)
                shot_cells.append(
                    f'<div class="shot"><a href="{rp}" target="_blank"><img src="{rp}" alt="screenshot"></a></div>'
                )
            shots_html = '<div class="shots">' + "".join(shot_cells) + "</div>"
        else:
            shots_html = '<small class="muted">스크린샷 없음</small>'

        # --- URLs (HTML) ---
        urls = _to_strings(urls)
        urls_html = (
            "<br>".join(urls[:120])
            if urls
            else '<small class="muted">수집된 URL 없음</small>'
        )

        # --- raw JSON embeds (bottom, details) ---
        static_json_embed = _pretty(static_result)
        dynamic_json_embed = _pretty(dynamic_result)

        return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>분석 리포트 · {app_name}</title>
<style>
  body {{ font-family: -apple-system,Segoe UI,Roboto,Arial,sans-serif; margin: 24px; color:#222; }}
  h1,h2,h3 {{ margin: 0.4em 0; }}
  .muted {{ color:#666; }}
  .grid {{ display:grid; grid-template-columns: 1fr 1fr; gap:18px; }}
  .card {{ border:1px solid #e5e5e5; border-radius:10px; padding:14px; background:#fff; }}
  .kv td:first-child {{ width:160px; color:#555; }}
  table.kv {{ border-collapse:collapse; }}
  table.kv td {{ padding:4px 8px; border-bottom:1px dashed #eee; vertical-align:top; }}
  .shots {{ display:flex; flex-wrap:wrap; gap:10px; }}
  .shot img {{ width:220px; height:auto; border:1px solid #ddd; border-radius:8px; }}
  code, pre {{ background:#fafafa; border:1px solid #eee; padding:10px; border-radius:8px; }}
  details {{ margin-top: 18px; }}
</style>
</head>
<body>

<h1>분석 리포트</h1>
<p class="muted">{self.apk_stem} · 패키지 <b>{package}</b> · 버전 {version} · targetSdk {target_sdk}</p>

<div class="grid">
  <div class="card">
    <h2>정적 요약</h2>
    <table class="kv">
      <tr><td>앱 이름</td><td>{app_name}</td></tr>
      <tr><td>패키지</td><td>{package}</td></tr>
      <tr><td>버전</td><td>{version}</td></tr>
      <tr><td>MD5</td><td>{md5}</td></tr>
      <tr><td>권한 수</td><td>{len(permissions)}</td></tr>
      <tr><td>Exported</td>
          <td>
            Activity {len(exported_acts)} / Service {len(exported_svcs)} / Receiver {len(exported_rcvs)}<br>
            <small class="muted">상세 목록은 정적 원문 JSON 참고</small>
          </td></tr>
    </table>
  </div>

  <div class="card">
    <h2>동적 요약</h2>
    <table class="kv">
      <tr><td>요약</td><td>{dyn_summary or "(요약 없음)"}</td></tr>
      <tr><td>Frida</td><td>{"ON" if frida_meta else "OFF/없음"}</td></tr>
      <tr><td>관측 URL</td><td>{len(urls)}</td></tr>
      <tr><td>첨부 링크</td><td>{links_html}</td></tr>
    </table>
  </div>
</div>

<div class="card" style="margin-top:18px;">
  <h2>네트워크 URL Top (최대 120개)</h2>
  <div>{urls_html}</div>
</div>

<div class="card" style="margin-top:18px;">
  <h2>스크린샷</h2>
  {shots_html}
</div>

<!-- Raw JSON은 페이지 맨 아래 접기영역 -->
<details>
  <summary><b>원문 JSON 보기 (정적)</b></summary>
  <pre>{static_json_embed}</pre>
</details>

<details>
  <summary><b>원문 JSON 보기 (동적)</b></summary>
  <pre>{dynamic_json_embed}</pre>
</details>

<p class="muted" style="margin-top:24px">자동 생성 리포트 · ReportResult.py</p>
</body></html>
"""

    def _build_text_summary(
        self, static_result: Dict[str, Any], dynamic_result: Dict[str, Any]
    ) -> str:
        apk_meta = static_result.get("apk_info") or static_result.get("apk_meta") or {}
        app_name = apk_meta.get("app_name") or self.apk_stem
        package = apk_meta.get("package_name") or apk_meta.get("package") or "N/A"
        version = apk_meta.get("version_name") or apk_meta.get("version") or "N/A"

        exported_acts = _coerce_list_str(
            (static_result.get("report") or {}).get("exported_activities")
        )
        exported_svcs = _coerce_list_str(
            (static_result.get("report") or {}).get("exported_services")
        )
        exported_rcvs = _coerce_list_str(
            (static_result.get("report") or {}).get("exported_receivers")
        )
        permissions = _coerce_list_str(
            (static_result.get("report") or {}).get("permissions")
        )

        dyn_summary = _safe_str(dynamic_result.get("summary") or "")
        urls = _coerce_urls(
            dynamic_result.get("urls") or dynamic_result.get("network") or []
        )

        lines: List[str] = []
        lines.append("=" * 50)
        lines.append("MobSF 통합 요약 보고서")
        lines.append("=" * 50)
        lines.append(f"▪ 앱: {app_name}")
        lines.append(f"▪ 패키지: {package}")
        lines.append(f"▪ 버전: {version}")
        lines.append("")
        lines.append("--- 정적 ---")
        lines.append(f"  - 권한: {len(permissions)}개")
        lines.append(
            f"  - Exported: Activity {len(exported_acts)} / Service {len(exported_svcs)} / Receiver {len(exported_rcvs)}"
        )
        lines.append("")
        lines.append("--- 동적 ---")
        lines.append(f"  - 요약: {dyn_summary or '(없음)'}")
        lines.append(f"  - 관측 URL: {len(urls)}개")
        lines.append("")
        lines.append("=" * 50)
        lines.append("※ 자동 생성 리포트이며, 수동 검증이 추가로 필요할 수 있습니다.")
        return "\n".join(lines)
