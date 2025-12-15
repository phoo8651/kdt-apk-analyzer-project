# KDT APK Analyzer

간단한 APK 정적·동적 분석 도구 모음입니다. 이 저장소는 MobSF(Mobile Security Framework)과 연동하여 APK의 정적 분석(스크래핑, 권한, 서명 등)과 선택적으로 Frida 기반 동적 분석을 수행하도록 설계되어 있습니다.

**주요 기능**
- MobSF API를 사용한 정적 분석 자동화
- (선택) Frida 스크립트를 이용한 런타임 후킹/로그 수집
- 분석 결과를 HTML 리포트로 결합
- Enc/Dec(DEX 의심 파일) 보조 리포트 생성

## 요구사항
- Python 3.8+
- 운영체제: Windows / Linux / macOS (일부 스크립트는 Windows 전용 배치/PowerShell 제공)
- 필수 Python 패키지: `requests`, `tzdata`, `pycryptodome`, `frida-tools` (자세한 내용은 `requirements.txt` 참조)
- MobSF 서버(정적 분석) 사용 시 `MOBSF_URL` 및 `MOBSF_API_KEY` 필요

## 빠른 시작 (Windows PowerShell)
1. 의존성 설치
```powershell
python -m pip install -r requirements.txt
```

2. (선택) MobSF를 로컬에서 실행하거나 원격 MobSF 서버를 준비합니다. API Key와 URL을 확인하세요.

3. `run.py`로 간단 분석 실행
```powershell
# 환경 변수 방식
$env:MOBSF_API_KEY = 'your_api_key_here'; $env:MOBSF_URL = 'http://127.0.0.1:8000'
python .\run.py C:\path\to\sample.apk --verbose

# 또는 CLI 인자로 직접 전달
python .\run.py C:\path\to\sample.apk --mobsf-url http://127.0.0.1:8000 --mobsf-api-key your_api_key_here --verbose
```

4. 결과는 기본값으로 `Result/` 디렉터리에 생성됩니다. 로그는 `Log/`에 남습니다.

## 구성 방법
- 프로젝트 루트에 `config.py`를 추가하면 `run.py` 실행 시 기본 설정으로 사용됩니다. 예시:

```python
class Config:
		VERBOSE = False
		DEVICE = 'emulator-5554'
		MOBSF_URL = 'http://127.0.0.1:8000'
		MOBSF_API_KEY = 'your_api_key'
		AAPT_PATH = None
		KEEP_CACHE = True

```

`run.py`의 CLI 인자는 `config.py`보다 우선합니다.

## 개발자 가이드
- 주요 코드 위치
	- `run.py` — 실행 진입점
	- `Module/StaticAnalysis.py` — MobSF 통신 및 정적분석 래퍼
	- `Module/DynamicAnalysis.py` — Frida 기반 동적 분석 로직
	- `Module/ReportResult.py` — 정적/동적 결과를 합쳐 HTML 리포트 생성
	- `MobSF/scripts/` — MobSF 관련 유틸 스크립트

- 안전성 개선: `MobSF/scripts/update_android_permissions.py`에서 `eval` 기반 실행을 제거하고 안전한 모듈 로드 방식으로 교체했습니다.

## 테스트
- 단위 테스트는 제공되지 않습니다. 수동 테스트 방법:
	- MobSF 서버와 연동하여 `run.py`로 실제 APK를 분석해 보세요.
	- 정적 분석만 확인하려면 `MOBSF_URL`/`MOBSF_API_KEY`가 필요합니다.

## 기여
- 이 저장소는 학습/연구 목적으로 사용됩니다. PR은 환영합니다.
- 주요 변경 전에는 이슈로 제안해 주세요.

## 라이선스
- 기본 프로젝트 라이선스 파일(`LICENSE`)을 확인하세요.

---
문제가 발견되거나 추가로 개선할 부분(예: 테스트, CI 설정, 보안 스캔)을 진행하길 원하시면 알려주세요.
## Project status
