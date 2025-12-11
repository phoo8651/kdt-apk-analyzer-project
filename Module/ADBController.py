# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
import shutil
import subprocess
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import List, Optional, Tuple, Union

try:
    # 선택: 있으면 기본값 사용
    from config import Config
except Exception:
    Config = None


class ADBError(Exception):
    """ADB 관련 예외"""


def _which(exe: Optional[str]) -> Optional[str]:
    """절대경로면 그대로, 아니면 PATH에서 탐색."""
    if not exe:
        return None
    p = Path(exe)
    if p.exists():
        return str(p)
    return shutil.which(exe)


class ADBController:
    """
    ADB 명령 제어 헬퍼
      - 기기 연결/부팅 대기/상태 확인
      - 앱 설치/실행/브로드캐스트/서비스
      - 스크린샷/로그캣 캡처/스크린레코딩
    """

    def __init__(
        self,
        device_id: str,
        log_dir: Path,
        verbose: bool = False,
        adb_path: Optional[str] = None,
        default_timeout: int = 20,
        default_retries: int = 0,
    ):
        """
        Args:
          device_id: ADB 대상 장비(-s 인자)
          log_dir: 로그 디렉터리 (자동 생성)
          verbose: 콘솔 출력 활성화 여부
          adb_path: 명시적 ADB 경로(미지정 시 config 또는 PATH 탐색)
          default_timeout: 개별 명령 기본 타임아웃(초)
          default_retries: 실패 시 재시도 횟수
        """
        self.device_id = device_id
        self.default_timeout = int(default_timeout)
        self.default_retries = int(default_retries)

        # adb 경로 결정: 인자 > config.ADB_PATH > PATH
        cfg = Config() if (Config is not None) else None
        self.adb = _which(adb_path or (getattr(cfg, "ADB_PATH", None) if cfg else None) or "adb")
        if not self.adb:
            raise ADBError("adb 를 찾을 수 없습니다. PATH 또는 config.ADB_PATH 를 확인하세요.")

        # 로깅
        log_dir.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger(f"ADBController[{self.device_id}]")
        self._logger.setLevel(logging.INFO)
        # 중복 핸들러 방지
        if self._logger.hasHandlers():
            self._logger.handlers.clear()

        # 파일 로테이션 핸들러 (최대 5MB, 백업 3개)
        file_handler = RotatingFileHandler(
            str(log_dir / "adb.log"), mode="a", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self._logger.addHandler(file_handler)

        if verbose:
            sh = logging.StreamHandler()
            sh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
            self._logger.addHandler(sh)

        self._logger.info(f"ADB: {self.adb} | DEVICE: {self.device_id}")

        # 로그캣/스크린레코더 프로세스 핸들
        self._logcat_proc: Optional[subprocess.Popen] = None
        self._screenrec_proc: Optional[subprocess.Popen] = None

    # ---------- 내부 유틸 ----------

    def _adb(self, *args: str) -> List[str]:
        """장비 지정이 포함된 adb 커맨드 배열 구성."""
        return [self.adb, "-s", self.device_id, *args]

    def _run(
        self,
        cmd: List[str],
        timeout: Optional[int] = None,
        check: bool = False,
        retries: Optional[int] = None,
    ) -> subprocess.CompletedProcess:
        """
        공통 실행 함수. 타임아웃/재시도/에러 로그 처리.
        """
        last_err = None
        tries = (self.default_retries if retries is None else retries) + 1
        for attempt in range(1, tries + 1):
            try:
                self._logger.info("ADB 실행: %s", " ".join(cmd))
                cp = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout or self.default_timeout,
                    encoding="utf-8",
                    errors="ignore",
                    shell=False,
                )
                if check and cp.returncode != 0:
                    raise ADBError(cp.stderr.strip() or f"returncode={cp.returncode}")
                return cp
            except subprocess.TimeoutExpired as e:
                last_err = e
                self._logger.warning("타임아웃 (시도 %d/%d): %s", attempt, tries, " ".join(cmd))
            except Exception as e:
                last_err = e
                self._logger.error("실행 실패 (시도 %d/%d): %s | %s", attempt, tries, " ".join(cmd), e)
            if attempt < tries:
                time.sleep(0.6)
        # 모두 실패
        if isinstance(last_err, subprocess.TimeoutExpired):
            raise ADBError(f"명령 타임아웃: {' '.join(cmd)}")
        raise ADBError(f"명령 실패: {' '.join(cmd)} | {last_err}")

    def _stdout_ok(self, cp: subprocess.CompletedProcess) -> Optional[str]:
        if cp.returncode == 0:
            return (cp.stdout or "").strip()
        self._logger.error("ADB 오류: rc=%s, stderr=%s", cp.returncode, (cp.stderr or "").strip())
        return None

    # ---------- 상태 확인/대기 ----------

    def is_device_online(self) -> bool:
        """-s <dev> get-state == 'device' 확인."""
        try:
            cp = self._run(self._adb("get-state"))
            out = (cp.stdout or cp.stderr or "").strip()
            ok = ("device" in out.lower())
            self._logger.info("기기 상태: %s", out)
            return ok
        except Exception as e:
            self._logger.error("기기 상태 확인 실패: %s", e)
            return False

    def wait_for_device(self, timeout: int = 60) -> bool:
        """adb wait-for-device & 간단 ping."""
        end = time.time() + timeout
        try:
            # 기본 wait
            self._run(self._adb("wait-for-device"), timeout=timeout, check=False)
        except Exception:
            pass
        while time.time() < end:
            if self.is_device_online():
                return True
            time.sleep(1.0)
        return False

    def wait_boot_completed(self, timeout: int = 120) -> bool:
        """sys.boot_completed == 1 대기."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                cp = self._run(self._adb("shell", "getprop", "sys.boot_completed"), check=False)
                if (cp.stdout or "").strip() == "1":
                    return True
            except Exception:
                pass
            time.sleep(1.0)
        return False

    # ---------- 앱/프로세스 ----------

    def install_apk(self, apk_path: Union[str, Path], replace: bool = True, grant_runtime_perms: bool = True) -> bool:
        """apk 설치(-r, -g)."""
        apk_path = str(Path(apk_path))
        args = ["install"]
        if replace:
            args.append("-r")
        if grant_runtime_perms:
            args.append("-g")
        args.append(apk_path)
        cp = self._run(self._adb(*args), check=False, timeout=180)
        ok = (cp.returncode == 0)
        if not ok:
            self._logger.error("설치 실패: %s", cp.stderr)
        return ok

    def uninstall(self, package_name: str, keep_data: bool = False) -> bool:
        """앱 제거. keep_data=True면 -k 옵션."""
        args = ["uninstall"]
        if keep_data:
            args.append("-k")
        args.append(package_name)
        cp = self._run(self._adb(*args), check=False)
        out = (cp.stdout or "").strip().lower()
        return "success" in out

    def start_app(self, package_name: str, activity: Optional[str] = None) -> bool:
        """액티비티 있으면 am start -n, 없으면 monkey로 런치."""
        if activity:
            cp = self._run(self._adb("shell", "am", "start", "-n", f"{package_name}/{activity}"), check=False)
            return cp.returncode == 0
        cp = self._run(
            self._adb(
                "shell",
                "monkey",
                "-p",
                package_name,
                "-c",
                "android.intent.category.LAUNCHER",
                "-v",
                "1",
            ),
            check=False,
        )
        return cp.returncode == 0

    def start_activity(self, component: str) -> bool:
        """am start -n <pkg/.Activity>"""
        cp = self._run(self._adb("shell", "am", "start", "-n", component), check=False)
        return cp.returncode == 0

    def start_service(self, component: str) -> bool:
        """am startservice <pkg/.Service>"""
        cp = self._run(self._adb("shell", "am", "startservice", component), check=False)
        return cp.returncode == 0

    def send_broadcast(self, action_name: str) -> bool:
        """am broadcast -a <ACTION>"""
        cp = self._run(self._adb("shell", "am", "broadcast", "-a", action_name), check=False)
        return cp.returncode == 0

    def pidof(self, package_name: str) -> Optional[str]:
        """pidof <pkg>"""
        cp = self._run(self._adb("shell", "pidof", package_name), check=False)
        pid = (cp.stdout or "").strip()
        return pid or None

    # ---------- 테스트/자동화 ----------

    def run_monkey_test(self, package_name: str, duration: int, throttle_ms: int = 300, batch_events: int = 50) -> None:
        """
        지정 시간동안 배치로 monkey 실행(타임아웃 분할).
        """
        self._logger.info("ADB Monkey 시작: pkg=%s, duration=%ss", package_name, duration)
        end = time.time() + max(1, duration)
        while time.time() < end:
            self._run(
                self._adb(
                    "shell",
                    "monkey",
                    "-p",
                    package_name,
                    "--throttle",
                    str(throttle_ms),
                    "-v",
                    str(batch_events),
                ),
                timeout=min(30, self.default_timeout),
                check=False,
            )
            time.sleep(0.8)
        self._logger.info("ADB Monkey 완료")

    # ---------- 파일/스크린샷 ----------

    def take_screenshot(self, local_path: Union[str, Path]) -> bool:
        """
        screencap -> pull -> rm (권한 문제 적은 tmp 사용)
        """
        local_path = Path(local_path)
        device_tmp = "/data/local/tmp/screen.png"
        ok = True
        try:
            self._run(self._adb("shell", "screencap", "-p", device_tmp), check=True)
            self._run(self._adb("pull", device_tmp, str(local_path)), check=True, timeout=60)
        except Exception as e:
            self._logger.error("스크린샷 실패: %s", e)
            ok = False
        finally:
            self._run(self._adb("shell", "rm", "-f", device_tmp), check=False)
        if ok:
            self._logger.info("📸 스크린샷 저장: %s", local_path)
        return ok

    def push(self, local_path: Union[str, Path], device_path: str) -> bool:
        cp = self._run(self._adb("push", str(local_path), device_path), check=False, timeout=120)
        return cp.returncode == 0

    def pull(self, device_path: str, local_path: Union[str, Path]) -> bool:
        cp = self._run(self._adb("pull", device_path, str(local_path)), check=False, timeout=120)
        return cp.returncode == 0

    # ---------- 로그캣 캡처 ----------

    def logcat_start(self, out_file: Union[str, Path], clear_first: bool = True, filterspec: Optional[List[str]] = None) -> None:
        """
        로그캡처 시작 (비동기).
        filterspec 예: ["*:E"] 또는 ["MyTag:D", "ActivityManager:I"]
        """
        if self._logcat_proc and self._logcat_proc.poll() is None:
            self._logger.warning("logcat 이미 실행 중입니다.")
            return
        try:
            if clear_first:
                self._run(self._adb("logcat", "-c"), check=False)
        except Exception:
            pass

        cmd = self._adb("logcat")
        if filterspec:
            cmd += filterspec

        out_path = Path(out_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        self._logger.info("logcat 캡처 시작 → %s", out_path)
        self._logcat_proc = subprocess.Popen(
            cmd, stdout=open(out_path, "a", encoding="utf-8"), stderr=subprocess.STDOUT, text=True
        )

    def logcat_stop(self) -> None:
        if self._logcat_proc and self._logcat_proc.poll() is None:
            self._logger.info("logcat 캡처 종료")
            self._logcat_proc.terminate()
            try:
                self._logcat_proc.wait(timeout=2)
            except Exception:
                self._logcat_proc.kill()
        self._logcat_proc = None

    # ---------- 스크린 레코딩 ----------

    def screenrecord_start(self, device_mp4: str = "/sdcard/record.mp4", bitrate_mbps: int = 4, size: Optional[str] = None) -> None:
        """
        adb shell screenrecord 실행 시작 (비동기). size 예: "720x1280"
        """
        if self._screenrec_proc and self._screenrec_proc.poll() is None:
            self._logger.warning("screenrecord 이미 실행 중입니다.")
            return
        args = ["shell", "screenrecord", f"--bit-rate", str(bitrate_mbps * 1_000_000)]
        if size:
            args += ["--size", size]
        args.append(device_mp4)
        cmd = self._adb(*args)
        self._logger.info("screenrecord 시작: %s", device_mp4)
        self._screenrec_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def screenrecord_stop(self) -> None:
        """screenrecord 중지 (프로세스 종료)."""
        if self._screenrec_proc and self._screenrec_proc.poll() is None:
            self._logger.info("screenrecord 종료")
            self._screenrec_proc.terminate()
            try:
                self._screenrec_proc.wait(timeout=2)
            except Exception:
                self._screenrec_proc.kill()
        self._screenrec_proc = None
