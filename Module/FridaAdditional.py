# -*- coding: utf-8 -*-
from __future__ import annotations
from pathlib import Path
from typing import List, Optional, Dict, Any
import subprocess
import shutil
import time
import sys
import os

try:
    from config import Config  # 선택: 경로/기본값 주입
except Exception:
    Config = None


class FridaError(Exception):
    pass


def _which(name: str) -> Optional[str]:
    """
    Windows 환경을 고려한 which. 절대경로면 그대로 반환.
    """
    if not name:
        return None
    p = Path(name)
    if p.exists():
        return str(p)
    found = shutil.which(name)
    return found


class FridaHelper:
    """
    - ADB 기반 앱 설치/실행/프로세스 제어
    - aapt로 패키지명 추출
    - frida CLI를 통해 스크립트 주입(spawn/attach)
    - stdout을 JSONL로 저장 (append)
    """

    DEFAULT_FRIDA_PORT = 27042

    def __init__(
        self,
        device: str = "emulator-5554",
        aapt_path: Optional[str] = None,
        frida_cli_path: Optional[str] = None,
        adb_path: Optional[str] = None,
        frida_port: Optional[int] = None,
        verbose: bool = False,
    ) -> None:
        self.verbose = verbose

        # Config 주입(있으면)
        cfg = Config() if (Config is not None) else None
        self.device = device or (cfg.DEVICE if cfg else "emulator-5554")
        self.aapt = aapt_path or (getattr(cfg, "AAPT_PATH", None) if cfg else None)
        self.frida_cli = frida_cli_path or (getattr(cfg, "FRIDA_CLI_PATH", None) if cfg else None)
        self.adb = adb_path or (getattr(cfg, "ADB_PATH", None) if cfg else None)
        self.frida_port = frida_port or (getattr(cfg, "FRIDA_PORT", None) if cfg else None) or self.DEFAULT_FRIDA_PORT

        # which
        self.adb = _which(self.adb or "adb")
        self.aapt = _which(self.aapt or "aapt")
        self.frida_cli = _which(self.frida_cli or "frida")

        if not self.adb:
            raise FridaError("adb 미발견: ANDROID_SDK platform-tools PATH 또는 config.ADB_PATH 확인 필요")
        if not self.frida_cli:
            # 필요 시 이후 실행 직전에 예외 발생하도록 두어도 되지만, 여기서 선제 확인
            raise FridaError("frida CLI 미발견: PATH 또는 config.FRIDA_CLI_PATH 확인 필요")

        # 유틸 경로 출력(선택)
        if self.verbose:
            print(f"[*] ADB: {self.adb}")
            print(f"[*] AAPT: {self.aapt or '(미설정)'}")
            print(f"[*] FRIDA: {self.frida_cli}")
            print(f"[*] DEVICE: {self.device} | FRIDA_PORT: {self.frida_port}")

    # ------------------- 내부 실행 유틸 -------------------

    def _run(self, cmd: List[str], timeout: Optional[int] = None, check: bool = False) -> subprocess.CompletedProcess:
        if self.verbose:
            print("[FridaHelper]$", " ".join(cmd))
        try:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout or 30, shell=False)
            if check and cp.returncode != 0:
                raise FridaError(f"명령 실패({cp.returncode}): {' '.join(cmd)}\nSTDERR: {cp.stderr}")
            return cp
        except subprocess.TimeoutExpired:
            raise FridaError(f"명령 타임아웃: {' '.join(cmd)}")

    def _adb(self, *args: str) -> List[str]:
        base = [self.adb]
        if self.device:
            base += ["-s", self.device]
        return base + list(args)

    # ------------------- ADB/장비 준비 -------------------

    def prepare(self) -> None:
        """
        - (옵션) frida-server 사용 시 포트 포워딩
        - 에뮬레이터/기기 연결성 점검
        """
        # 연결 점검
        out = self._run(self._adb("get-state"))
        state = (out.stdout or out.stderr or "").strip()
        if self.verbose:
            print(f"[*] ADB state: {state}")

        # 포트 포워딩 (로컬→원격 동일 포트)
        self._run(self._adb("forward", f"tcp:{self.frida_port}", f"tcp:{self.frida_port}"), check=False)

    # ------------------- APK 설치/패키지 추출/앱 실행 -------------------

    def install_apk(self, apk_path: Path) -> subprocess.CompletedProcess:
        apk_path = Path(apk_path)
        return self._run(self._adb("install", "-r", str(apk_path)))

    def get_package_name_via_aapt(self, apk_path: Path) -> Optional[str]:
        """
        aapt dump badging 결과에서 package name 추출.
        aapt 미설정인 경우 None.
        """
        if not self.aapt:
            return None
        try:
            cp = self._run([self.aapt, "dump", "badging", str(apk_path)], timeout=10)
            if cp.returncode == 0 and "package: name='" in (cp.stdout or ""):
                for l in (cp.stdout or "").splitlines():
                    if l.startswith("package: name="):
                        return l.split("package: name='")[1].split("'")[0]
        except Exception:
            pass
        return None

    def launch_app(self, package: str, component: Optional[str] = None) -> subprocess.CompletedProcess:
        """
        component가 있으면 'am start -n pkg/Component', 없으면 monkey 1 event
        """
        if component:
            return self._run(self._adb("shell", "am", "start", "-n", f"{package}/{component}"))
        return self._run(self._adb("shell", "monkey", "-p", package, "-c",
                                   "android.intent.category.LAUNCHER", "-v", "1"))

    def pidof(self, package: str) -> Optional[str]:
        cp = self._run(self._adb("shell", "pidof", package))
        pid = (cp.stdout or "").strip()
        return pid or None

    # ------------------- Frida 실행 -------------------

    def run_frida(
        self,
        package: str,
        script_path: Path,
        jsonl_out: Path,
        mode: str = "spawn",
        seconds: int = 10,
        runtime: str = "v8",
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        mode: 'spawn' | 'attach' (spawn 권장)
        - stdout/stderr을 JSONL 파일에 append 저장
        - seconds 후 프로세스 종료 시도
        반환: {'returncode':int|None, 'pid':int|None, 'args':[...], 'log':path}
        """
        script_path = Path(script_path)
        if not script_path.exists():
            raise FridaError(f"Frida 스크립트가 존재하지 않습니다: {script_path}")

        jsonl_out = Path(jsonl_out)
        jsonl_out.parent.mkdir(parents=True, exist_ok=True)

        args = [self.frida_cli or "frida", "-q", "-D", self.device]
        mode = (mode or "spawn").lower()

        if mode == "attach":
            if not self.pidof(package):
                # 앱이 안 떠 있으면 기동 후 attach
                try:
                    self.launch_app(package)
                    time.sleep(1.0)
                except Exception:
                    pass
            args += ["-n", package]
        else:
            # spawn 모드(기본)
            args += ["-f", package]

        args += ["-l", str(script_path)]
        if runtime:
            args += ["--runtime", runtime]
        if extra_args:
            args += extra_args

        if self.verbose:
            print(f"[*] frida 호출 인자: {' '.join(args)}")
            print(f"[*] 로그: {jsonl_out}")

        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        start = time.time()
        pid = proc.pid

        # 스트리밍으로 JSONL에 append
        with open(jsonl_out, "a", encoding="utf-8") as logf:
            try:
                while True:
                    line = proc.stdout.readline() if proc.stdout else ""
                    if line:
                        logf.write(line)
                        # 버퍼 적재 시점 보장
                        logf.flush()
                    # 시간 제한 확인
                    if seconds and (time.time() - start) > seconds:
                        break
                    # 프로세스 종료 감지
                    if proc.poll() is not None:
                        break
                    # 살짝 대기
                    time.sleep(0.02)
            finally:
                # 부드럽게 종료 시도
                if proc and proc.poll() is None:
                    if self.verbose:
                        print("[*] frida 프로세스 종료 시도 (terminate)")
                    proc.terminate()
                    time.sleep(0.8)
                if proc and proc.poll() is None:
                    if self.verbose:
                        print("[*] frida 프로세스 강제 종료 (kill)")
                    proc.kill()

        return {"returncode": proc.returncode, "pid": pid, "args": args, "log": str(jsonl_out)}
