# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import hashlib
import math
import struct
from pathlib import Path
from typing import Dict, List, Tuple

# PDF
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

DEX_MAGIC_PREFIX = b"dex\n"  # b'd','e','x','\n'
DEX_VERSIONS = {b"035\x00", b"036\x00", b"037\x00", b"038\x00", b"039\x00"}  # 표준/ART

def read_file_bytes(p: Path) -> bytes:
    return p.read_bytes()

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def calc_entropy(data: bytes, sample_len: int = 256_000) -> float:
    """샤논 엔트로피 (샘플링, 최대 256KB). 0~8 비트/바이트"""
    if not data:
        return 0.0
    buf = data[:sample_len]
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    ent = 0.0
    n = len(buf)
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log(p, 2)
    return ent

def find_dex_offsets(data: bytes, limit: int = 16) -> List[int]:
    """파일 내부의 모든 'dex\\n???\\x00' 위치 탐색 (상위 limit개)"""
    offs: List[int] = []
    i = 0
    end = max(0, len(data) - 8)
    while i <= end and len(offs) < limit:
        j = data.find(DEX_MAGIC_PREFIX, i)
        if j < 0:
            break
        # 버전 4바이트 검증
        if j + 8 <= len(data):
            ver = data[j + 4 : j + 8]
            if ver in DEX_VERSIONS:
                offs.append(j)
        i = j + 1
    return offs

def parse_dex_header(data: bytes, base_off: int = 0) -> Dict[str, int | str]:
    """DEX 헤더 파싱 (https://source.android.com/docs/core/runtime/dex-format#header-item)"""
    # struct layout (little-endian)
    # magic[8], checksum uint32, signature[20],
    # file_size, header_size, endian_tag, link_size, link_off, map_off,
    # string_ids_size, string_ids_off,
    # type_ids_size, type_ids_off,
    # proto_ids_size, proto_ids_off,
    # field_ids_size, field_ids_off,
    # method_ids_size, method_ids_off,
    # class_defs_size, class_defs_off,
    # data_size, data_off (모두 uint32)
    off = base_off
    need = 0x70  # 헤더 최소 0x70 bytes
    if off + need > len(data):
        raise ValueError("Not enough data for DEX header")

    magic = data[off : off + 8]
    if not (magic[:4] == DEX_MAGIC_PREFIX and magic[4:8] in DEX_VERSIONS):
        raise ValueError("Not a valid DEX magic at given offset")

    (
        checksum,
        # signature 20B => skip with slice
        file_size,
        header_size,
        endian_tag,
        link_size,
        link_off,
        map_off,
        string_ids_size, string_ids_off,
        type_ids_size, type_ids_off,
        proto_ids_size, proto_ids_off,
        field_ids_size, field_ids_off,
        method_ids_size, method_ids_off,
        class_defs_size, class_defs_off,
        data_size, data_off,
    ) = struct.unpack_from("<I20xI I I I I I I I I I I I I I I", data, off + 8)

    return {
        "magic": magic,
        "version": magic[4:8].decode("ascii", errors="ignore"),
        "checksum": checksum,
        "file_size": file_size,
        "header_size": header_size,
        "endian_tag": endian_tag,
        "link_size": link_size, "link_off": link_off,
        "map_off": map_off,
        "string_ids_size": string_ids_size, "string_ids_off": string_ids_off,
        "type_ids_size": type_ids_size, "type_ids_off": type_ids_off,
        "proto_ids_size": proto_ids_size, "proto_ids_off": proto_ids_off,
        "field_ids_size": field_ids_size, "field_ids_off": field_ids_off,
        "method_ids_size": method_ids_size, "method_ids_off": method_ids_off,
        "class_defs_size": class_defs_size, "class_defs_off": class_defs_off,
        "data_size": data_size, "data_off": data_off,
        "_base": base_off,
    }

def read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """ULEB128 read → (value, bytes_consumed)"""
    result = 0
    shift = 0
    i = 0
    while True:
        b = data[offset + i]
        result |= (b & 0x7F) << shift
        i += 1
        if (b & 0x80) == 0:
            break
        shift += 7
        if i > 5:
            raise ValueError("ULEB128 too long")
    return result, i

def extract_strings(data: bytes, hdr: Dict[str, int | str], base_off: int, max_count: int = 200) -> List[str]:
    """DEX 문자열 테이블 일부 추출 (안전 모드, 오류 무시)"""
    out: List[str] = []
    size = int(hdr["string_ids_size"])  # type: ignore[arg-type]
    off = int(hdr["string_ids_off"])    # type: ignore[arg-type]
    if size == 0 or off == 0:
        return out
    # string_id_item: uint32 string_data_off (파일 기준)
    for i in range(min(size, max_count)):
        item_off = base_off + off + i * 4
        if item_off + 4 > len(data):
            break
        (str_off,) = struct.unpack_from("<I", data, item_off)
        str_off_abs = base_off + str_off
        if str_off_abs >= len(data):
            continue
        # string_data_item: uleb128 (utf16_size), followed by MUTF-8 bytes (null-terminated)
        try:
            strlen, used = read_uleb128(data, str_off_abs)
            s_start = str_off_abs + used
            # MUTF-8 은 0x00으로 종료(단, MUTF-8 규칙은 복잡하지만 대충 가독용 추출)
            end = data.find(b"\x00", s_start, min(len(data), s_start + 10_000))
            if end == -1:
                end = min(len(data), s_start + 512)
            s = data[s_start:end].decode("utf-8", errors="ignore")
            out.append(s)
        except Exception:
            continue
    return out

def summarize_urls(strings: List[str], limit: int = 200) -> List[str]:
    urls = []
    for s in strings[:limit]:
        ls = s.lower()
        if ls.startswith("http://") or ls.startswith("https://"):
            urls.append(s)
        elif "://" in ls and any(proto in ls for proto in ("http", "https")):
            urls.append(s)
    # 중복 제거
    seen = set()
    uniq = []
    for u in urls:
        if u not in seen:
            uniq.append(u)
            seen.add(u)
    return uniq

def make_pdf(
    out_pdf: Path,
    file_path: Path,
    file_bytes: bytes,
    dex_infos: List[Dict],
    strings_map: Dict[int, List[str]],
) -> None:
    styles = getSampleStyleSheet()
    story = []

    title = f"APK Analyzer - Suspicious DEX Report"
    story.append(Paragraph(f"<b>{title}</b>", styles["Title"]))
    story.append(Spacer(1, 6))

    # 기본 메타
    info_tbl = [
        ["Input Path", str(file_path)],
        ["Size (bytes)", f"{len(file_bytes):,}"],
        ["SHA-256", sha256(file_bytes)],
        ["MD5", md5(file_bytes)],
        ["Entropy (sample)", f"{calc_entropy(file_bytes):.3f} bits/byte (max 8.0)"],
    ]
    t = Table(info_tbl, colWidths=[40*mm, 135*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.whitesmoke),
        ("BOX", (0,0), (-1,-1), 0.25, colors.black),
        ("INNERGRID", (0,0), (-1,-1), 0.25, colors.lightgrey),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    if not dex_infos:
        story.append(Paragraph(
            "<font color='red'><b>DEX magic을 찾지 못했습니다.</b></font> "
            "파일이 암호화/압축/인코딩 되었거나 DEX가 포함되지 않았을 수 있습니다.",
            styles["BodyText"]
        ))
    else:
        for idx, hdr in enumerate(dex_infos):
            base = hdr["_base"]
            story.append(Paragraph(f"<b>DEX #{idx} @ offset {base} (version {hdr['version']!s})</b>", styles["Heading2"]))
            rows = [
                ["Offset", str(base)],
                ["Version", str(hdr["version"])],
                ["file_size", f"{hdr['file_size']:,}"],
                ["header_size", f"{hdr['header_size']:,}"],
                ["endian_tag", hex(hdr["endian_tag"])],
                ["string_ids_size/off", f"{hdr['string_ids_size']} @ {hdr['string_ids_off']}"],
                ["type_ids_size/off", f"{hdr['type_ids_size']} @ {hdr['type_ids_off']}"],
                ["proto_ids_size/off", f"{hdr['proto_ids_size']} @ {hdr['proto_ids_off']}"],
                ["field_ids_size/off", f"{hdr['field_ids_size']} @ {hdr['field_ids_off']}"],
                ["method_ids_size/off", f"{hdr['method_ids_size']} @ {hdr['method_ids_off']}"],
                ["class_defs_size/off", f"{hdr['class_defs_size']} @ {hdr['class_defs_off']}"],
                ["data_size/off", f"{hdr['data_size']} @ {hdr['data_off']}"],
            ]
            ht = Table(rows, colWidths=[50*mm, 125*mm])
            ht.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (0,-1), colors.whitesmoke),
                ("BOX", (0,0), (-1,-1), 0.25, colors.black),
                ("INNERGRID", (0,0), (-1,-1), 0.25, colors.lightgrey),
            ]))
            story.append(ht)
            story.append(Spacer(1, 6))

            # 문자열 샘플
            s_list = strings_map.get(base, [])
            if s_list:
                story.append(Paragraph("<b>Extracted Strings (sample)</b>", styles["Heading3"]))
                # 표로 30개 내외 보여주기
                sample = s_list[:30]
                s_rows = [[f"{i+1}", sample[i]] for i in range(len(sample))]
                st = Table([["#", "String"]] + s_rows, colWidths=[10*mm, 165*mm])
                st.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
                    ("BOX", (0,0), (-1,-1), 0.25, colors.black),
                    ("INNERGRID", (0,0), (-1,-1), 0.25, colors.lightgrey),
                ]))
                story.append(st)
                story.append(Spacer(1, 6))

                # URL 후보
                urls = summarize_urls(s_list)
                story.append(Paragraph("<b>Possible URLs</b>", styles["Heading3"]))
                if urls:
                    url_rows = [[u] for u in urls[:30]]
                    ut = Table(url_rows, colWidths=[175*mm])
                    ut.setStyle(TableStyle([
                        ("BOX", (0,0), (-1,-1), 0.25, colors.black),
                        ("INNERGRID", (0,0), (-1,-1), 0.25, colors.lightgrey),
                    ]))
                    story.append(ut)
                else:
                    story.append(Paragraph("<i>No URLs detected in sample strings.</i>", styles["BodyText"]))
            else:
                story.append(Paragraph("<i>String table not found or empty.</i>", styles["BodyText"]))

            story.append(Spacer(1, 12))

    doc = SimpleDocTemplate(
        str(out_pdf),
        pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm, topMargin=15*mm, bottomMargin=15*mm
    )
    doc.build(story)

def analyze_and_export_pdf(input_path: Path, output_pdf: Path | None = None) -> Path:
    data = read_file_bytes(input_path)
    # 1) DEX 오프셋 찾기
    offsets = find_dex_offsets(data)

    dex_infos: List[Dict] = []
    strings_map: Dict[int, List[str]] = {}

    for off in offsets:
        try:
            hdr = parse_dex_header(data, off)
            dex_infos.append(hdr)
            # 문자열 일부 뽑기
            strings = extract_strings(data, hdr, base_off=off, max_count=200)
            strings_map[off] = strings
        except Exception:
            continue

    # 출력 경로
    if output_pdf is None:
        # 파일명.pdf (원본 확장자 제거)
        stem = input_path.stem
        output_pdf = input_path.with_name(f"{stem}_analysis.pdf")

    make_pdf(output_pdf, input_path, data, dex_infos, strings_map)
    return output_pdf

def main():
    ap = argparse.ArgumentParser(description="Analyze suspicious .sus (DEX-like) file and export PDF report.")
    ap.add_argument("input", type=str, help="Path to .sus (or any) binary")
    ap.add_argument("-o", "--output", type=str, default="", help="Output PDF path")
    args = ap.parse_args()

    in_path = Path(args.input).resolve()
    if not in_path.exists():
        raise SystemExit(f"Input not found: {in_path}")

    out = Path(args.output).resolve() if args.output else None
    pdf_path = analyze_and_export_pdf(in_path, out)
    print(f"[OK] PDF saved: {pdf_path}")

if __name__ == "__main__":
    main()
