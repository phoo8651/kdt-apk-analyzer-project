# -*- coding: utf-8 -*-
from __future__ import annotations
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
import zipfile, binascii, json

# DEX 매직 지원 범위 확장 (035, 037, 038, 039)
DEX_MAGICS = [b"dex\n035\x00", b"dex\n037\x00", b"dex\n038\x00", b"dex\n039\x00"]


def _is_dex_magic(head: bytes) -> bool:
    return any(head.startswith(m) for m in DEX_MAGICS)


def _read_jsonl(jsonl_path: Path) -> List[dict]:
    if not jsonl_path or not jsonl_path.exists():
        return []
    out = []
    for line in jsonl_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def _keys_from_events(events: List[dict]) -> List[dict]:
    ks = []
    for e in events:
        if e.get("type") == "crypto" and e.get("sub") == "init":
            key_hex = e.get("key_hex") or ""
            iv_hex = e.get("iv_hex") or ""
            algo = e.get("algo") or ""
            if key_hex:
                ks.append({"key_hex": key_hex, "iv_hex": iv_hex, "algo": algo})
    return ks


def _pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        return b
    pad = b[-1]
    if 1 <= pad <= 16 and b.endswith(bytes([pad]) * pad):
        return b[:-pad]
    return b


class EncDecAnalyzer:
    """
    - APK 내 DEX 파일 상태 점검(매직 검사)
    - 의심 페이로드 자동 탐지(헤더 비정상 dex + assets 후보)
    - Frida 이벤트로부터 키/IV 추출 후 복호화 시도(AES-ECB/CBC/CTR)
    - 결과를 dict로 반환 (Reporter와 run.py가 그대로 사용)
    """

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    # ---------------- DEX/의심파일 스캔 ----------------

    def analyze_dex(self, apk_path: Path) -> Dict[str, Any]:
        apk_path = Path(apk_path)
        out = {
            "apk": str(apk_path),
            "files": [],
            "summary": {"dex_total": 0, "dex_magic_ok": 0, "dex_suspect": 0},
        }
        suspects: List[str] = []

        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                lname = name.lower()
                if lname.endswith(".dex"):
                    with z.open(name, "r") as f:
                        head = f.read(8)
                        ok = _is_dex_magic(head)
                    info = z.getinfo(name)
                    out["files"].append(
                        {
                            "name": name,
                            "size": info.file_size,
                            "magic_ok": ok,
                            "head_hex": binascii.hexlify(head).decode(),
                        }
                    )
                    out["summary"]["dex_total"] += 1
                    out["summary"]["dex_magic_ok"] += 1 if ok else 0
                    out["summary"]["dex_suspect"] += 0 if ok else 1
                    if not ok:
                        suspects.append(name)
                else:
                    # 흔한 암호화 페이로드 후보 (경험적)
                    if lname.startswith("assets/") and lname.endswith(
                        (".dat", ".enc", ".bin", ".res", ".pack")
                    ):
                        suspects.append(name)

        # 중복 제거
        out["suspects"] = sorted(set(suspects))
        return out

    # ---------------- 복호화 시도 ----------------

    def _try_aes_decrypt(
        self, buf: bytes, key_hex: str, iv_hex: str
    ) -> Optional[bytes]:
        try:
            from Crypto.Cipher import AES
        except Exception:
            return None

        try:
            key = bytes.fromhex(key_hex)
        except Exception:
            return None
        iv = None
        if iv_hex:
            try:
                iv = bytes.fromhex(iv_hex)
            except Exception:
                iv = None

        outs: List[bytes] = []

        # AES-ECB
        try:
            if len(key) in (16, 24, 32):
                c = AES.new(key, AES.MODE_ECB)
                cut = (len(buf) // 16) * 16
                d = c.decrypt(buf[:cut])
                d = _pkcs7_unpad(d) + buf[cut:]
                outs.append(d)
        except Exception:
            pass

        # AES-CBC
        try:
            if iv:
                c = AES.new(key, AES.MODE_CBC, iv=iv[:16])
                cut = (len(buf) // 16) * 16
                d = c.decrypt(buf[:cut])
                d = _pkcs7_unpad(d) + buf[cut:]
                outs.append(d)
        except Exception:
            pass

        # AES-CTR (일부 앱이 사용)
        try:
            if iv:
                from Crypto.Util import Counter

                # CTR에서 iv/nonce 해석은 앱마다 상이 → 가장 단순한 16바이트 nonce로 가정
                nonce = iv[:8]
                ctr = Counter.new(64, prefix=nonce, initial_value=0)
                c = AES.new(key, AES.MODE_CTR, counter=ctr)
                d = c.decrypt(buf)
                outs.append(d)
        except Exception:
            pass

        for cand in outs:
            # 완전 선두 또는 앞부분에 DEX 매직 등장
            if any(cand.startswith(m) for m in DEX_MAGICS):
                return cand
            headscan = cand[:8192]
            for m in DEX_MAGICS:
                i = headscan.find(m)
                if i >= 0:
                    return cand[i:]
        return None

    def decrypt_suspects(
        self,
        apk_path: Path,
        encdex_info: Dict[str, Any],
        events_jsonl: Optional[Path],
        events_memory: Optional[List[dict]],
        out_dir: Path,
    ) -> Dict[str, Any]:
        """
        - APK 내부 suspect 항목 읽어 AES 복호화 시도
        - 키 소스: events_memory > events_jsonl
        - 결과물: out_dir/*.dec.dex 저장
        """
        out_dir.mkdir(parents=True, exist_ok=True)
        events: List[dict] = events_memory or []
        if events_jsonl and not events:
            events = _read_jsonl(events_jsonl)
        keys = _keys_from_events(events)

        results: List[dict] = []
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in encdex_info.get("suspects", []):
                try:
                    fb = z.read(name)
                except Exception as ex:
                    results.append(
                        {
                            "source": name,
                            "status": "read_fail",
                            "why": f"{type(ex).__name__}: {ex}",
                        }
                    )
                    continue

                ok = False
                for k in keys:
                    dec = self._try_aes_decrypt(
                        fb, k.get("key_hex", ""), k.get("iv_hex", "")
                    )
                    if dec:
                        dst = out_dir / (Path(name).name.replace("/", "_") + ".dec.dex")
                        dst.write_bytes(dec)
                        results.append(
                            {
                                "source": name,
                                "status": "decrypted",
                                "out": str(dst),
                                "key_hex": k.get("key_hex", ""),
                                "iv_hex": k.get("iv_hex", ""),
                            }
                        )
                        ok = True
                        break
                if not ok:
                    results.append({"source": name, "status": "failed"})

        return {"keys": keys, "results": results, "events_tail": events[-200:]}

    # ---------------- 라운드트립 검증(선택) ----------------

    def verify_roundtrip(
        self,
        events_jsonl: Optional[Path],
        out_dir: Path,
        events_memory: Optional[List[dict]] = None,
        max_cases: int = 5,
    ) -> List[dict]:
        try:
            from Crypto.Cipher import AES  # noqa: F401
        except Exception:
            return [{"error": "pycryptodome not installed"}]

        ev = events_memory or []
        if events_jsonl and not ev:
            ev = _read_jsonl(events_jsonl)

        meta: Dict[Any, Any] = {}
        for e in ev:
            if e.get("type") == "crypto" and e.get("sub") == "init":
                meta[e.get("id")] = {
                    "algo": e.get("algo", ""),
                    "opmode": e.get("opmode", ""),
                    "key": (
                        bytes.fromhex(e.get("key_hex", "")) if e.get("key_hex") else b""
                    ),
                    "iv": (
                        bytes.fromhex(e.get("iv_hex", "")) if e.get("iv_hex") else b""
                    ),
                }

        results: List[dict] = []
        for e in ev:
            if e.get("type") != "crypto":
                continue
            if not str(e.get("sub", "")).startswith("doFinal"):
                continue
            cid = e.get("id")
            phase = e.get("phase")
            algo = (e.get("algo") or "").upper()
            meta_c = meta.get(cid)
            in_path, out_path = e.get("in_path"), e.get("out_path")
            if not meta_c or not in_path or not out_path:
                continue

            try:
                ib = Path(in_path).read_bytes()
                ob = Path(out_path).read_bytes()
            except Exception:
                continue

            ok = False
            reason = ""
            try:
                from Crypto.Cipher import AES

                key, iv = meta_c["key"], meta_c["iv"]
                if not key:
                    raise ValueError("no key captured")

                if "AES" in (meta_c["algo"] or algo).upper():
                    if phase == "ENCRYPT":
                        if iv:
                            c = AES.new(key, AES.MODE_CBC, iv=iv[:16])
                        else:
                            c = AES.new(key, AES.MODE_ECB)
                        pad = (-len(ib)) % 16
                        buf = ib + (bytes([pad]) * pad if pad else b"")
                        test = c.encrypt(buf)
                        ok = ob.startswith(test[: len(ob)])
                    elif phase == "DECRYPT":
                        if iv:
                            c = AES.new(key, AES.MODE_CBC, iv=iv[:16])
                        else:
                            c = AES.new(key, AES.MODE_ECB)
                        cut = (len(ib) // 16) * 16
                        test = c.decrypt(ib[:cut])
                        ok = (
                            test[: min(len(test), len(ob))]
                            == ob[: min(len(test), len(ob))]
                        )
                    else:
                        reason = "phase not ENCRYPT/DECRYPT"
                else:
                    reason = "unsupported algo"
            except Exception as ex:
                reason = f"{type(ex).__name__}: {ex}"

            results.append(
                {
                    "cipher_id": cid,
                    "phase": phase,
                    "algo": (meta_c.get("algo") or algo).upper(),
                    "ok": bool(ok),
                    "in": in_path,
                    "out": out_path,
                    "why": reason,
                }
            )
            if len(results) >= max_cases:
                break

        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "crypto_verify.json").write_text(
            json.dumps(results, indent=2), encoding="utf-8"
        )
        return results
