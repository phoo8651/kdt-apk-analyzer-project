from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Config:
    """프로젝트 전역 설정 (Windows 우선).
    - CLI 인자 값이 존재하면 해당 값이 우선 적용
    - 디렉터리는 자동 생성
    """

    # 경로
    ROOT: Path = field(default_factory=lambda: Path(__file__).resolve().parent)
    LOG_DIR: Path = field(init=False)
    RESULT_DIR: Path = field(init=False)
    TEMPLATE_DIR: Path = field(init=False)
    AAPT_PATH: str = r"C:\Users\rorum\AppData\Local\Android\Sdk\build-tools\36.0.0\aapt.exe"

    # --- MobSF 서버 및 API 설정 ---
    MOBSF_URL: str = "http://127.0.0.1:8000"
    MOBSF_API_KEY: str = (
        "26464bdd0682c1dcf641c6896348542f1ad8e1a2447848143a53719a5e66da43"
    )

    # 암복호화 설정
    ENCDEC_ENABLED: bool = True
    ENCDEC_OUT_DIR_NAME: str = "encdec"  # Result/encdec/<apk_ts> 하위에 생성
    ENCDEC_EVENTS_JSONL: Optional[str] = None  # 별도 JSONL 이벤트 파일 경로

    # 디바이스/분석 옵션
    DEVICE: str = "emulator-5554"
    DYNAMIC_ENABLED: bool = True
    USE_FRIDA: bool = False
    OUT_FORMAT: str = "html"  # "html" | "xml"

    # 도구 경로/로깅
    AAPT_PATH: Optional[str] = None  # 예: r"C:\Android\build-tools\34.0.0\aapt.exe"
    VERBOSE: bool = False

    def __post_init__(self) -> None:
        self.LOG_DIR = self.ROOT / "Log"
        self.RESULT_DIR = self.ROOT / "Result"
        self.TEMPLATE_DIR = self.ROOT / "Templates"

    def ensure_dirs(self) -> None:
        self.LOG_DIR.mkdir(exist_ok=True, parents=True)
        self.RESULT_DIR.mkdir(exist_ok=True, parents=True)
        self.TEMPLATE_DIR.mkdir(exist_ok=True, parents=True)
