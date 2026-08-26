# vulnagent

> 이 디렉토리는 저장소 루트의 `LICENSE`(AGPL-3.0)를 따릅니다.

수집 에이전트가 MySQL에 쌓아둔 취약점 스캔 데이터를 읽어, LangGraph 기반 AI 에이전트가
**호스트별 실제 위험도를 분석**하고 **한국어 PDF 보고서**를 생성하는 서비스입니다.

- 단순 취약점 목록 나열이 아니라, 도달가능성·자산 중요도·데이터 신뢰도를 반영한 **결정론적
  위험점수/우선순위(P0~P3)** 를 먼저 계산하고, LLM은 그 위에서 "왜 문제이고 무엇을 해야
  하는지"를 서술합니다.
- 위험 분석 콘텐츠는 사이버보안 특화 로컬 LLM이 **영어**로 작성한 뒤, 번역 전용 모델로
  **한국어**로 번역합니다.
- 위협 인텔리전스(APT/위협 행위자 보고서) 벡터DB를 RAG로 검색해 배경 맥락을 보강합니다.
- LLM이 근거 없는 주장을 하지 않도록 프롬프트 단계 제약 + 렌더링 직전 자체 검증
  게이트(`report_qa`)를 두어, 검증에 실패하면 PDF를 만들지 않고 작업을 FAILED 처리합니다.

## 아키텍처

```
FastAPI(POST /jobs) --생성-→ Postgres(jobs 테이블, 상태 추적)
       |
       └-Celery(RabbitMQ 브로커)--→ Celery worker --→ LangGraph 파이프라인
                                                            |
                     MySQL(취약점 원본, 읽기 전용) ---------┤
                     사이버보안 전문 LLM(영어 생성) ---------┤
                     translategemma(영→한 번역) -------------┤
                     Qdrant + bge-m3(CTI 벡터 검색, RAG) ----┤
                                                            ↓
                                                    reports/job_{id}.pdf
```

| 구성요소 | 역할 | 비고 |
|---|---|---|
| FastAPI | 작업 생성/조회/PDF 다운로드 API | `app/main.py`, `app/api/jobs.py` |
| Postgres | 비동기 작업(Job) 상태 저장 | `app/database/models.py` (`jobs` 테이블) |
| Celery + RabbitMQ | 백그라운드 파이프라인 실행 | `app/workers/` |
| MySQL | 별도 수집 에이전트가 채워넣는 취약점 원본 데이터 (읽기 전용) | `app/queries/get_data.py` |
| LangGraph | 5단계 분석 파이프라인 | `app/agent/graph.py`, `app/agent/nodes.py` |
| 로컬 LLM (llama.cpp, 8080) | 위험 분석 서술을 영어로 생성 | `LLM_BASE_URL` |
| translategemma (8081) | 영어 → 한국어 번역 | `TRANSLATE_LLM_BASE_URL` |
| bge-m3 (8082) + Qdrant | CTI 문서 임베딩 검색(RAG) | `EMBEDDING_BASE_URL`, `QDRANT_URL` |
| WeasyPrint + Jinja2 | HTML → PDF 렌더링(한글 폰트 지원) | `app/agent/templates/report.html.jinja` |

## 사용 모델·라이선스

3개 모두 파인튜닝 없이 그대로 활용(외부 모델 그대로 활용 유형)하며, 전부 로컬 GPU 서버에서
직접 구동합니다(외부 상용 API 호출 아님).

| 모델(개발사) | 라이선스 | 용도 | HuggingFace |
|---|---|---|---|
| Qwen3.8-27B-Uncensored-Cyber-GGUF (philbert440, Qwen/Qwen3.8-27B 기반) | Apache License 2.0 | 사이버보안 위험분석 콘텐츠 생성(영어) | https://huggingface.co/philbert440/Qwen3.8-27B-Uncensored-Cyber-GGUF |
| TranslateGemma-27B-IT (Google) | Gemma 이용약관 (https://ai.google.dev/gemma/terms) | 영어 → 한국어 번역 | https://huggingface.co/google/translategemma-27b-it |
| BGE-M3 (BAAI) | MIT License | RAG 임베딩(위협 인텔리전스 벡터 검색) | https://huggingface.co/BAAI/bge-m3 |

## 분석 파이프라인 (LangGraph 5단계)

`app/agent/nodes.py`, `app/agent/graph.py` 참고.

1. **collect_data** — MySQL에서 호스트의 최신 스캔 원본 데이터를 읽어온다.
2. **triage_findings** — 전체 finding에 도달가능성/데이터검증상태/우선순위 티어(P0~P3/REVIEW)를
   *LLM 없이* 규칙 기반으로 부여하고, 조치 단위(컨테이너 x 패키지)로 그룹화한 뒤 CTI 배경
   맥락(RAG)을 붙인다.
3. **analyze_risks** — 조치 그룹별로 LLM에게 영어 위험 서술을 받고, 그룹 단위로 한국어 번역까지
   마친다.
4. **synthesize_narrative** — 보고서 전체 총평/권고/결론을 LLM으로 작성하고 번역한다.
5. **render_pdf** — `report_qa` 자체 검증을 통과한 경우에만 PDF를 렌더링한다. 실패하면
   `ReportQAError`를 던져 Celery가 작업을 FAILED로 남긴다(문제 있는 보고서가 사용자에게
   조용히 노출되지 않도록).

### 핵심 설계 원칙

- **결정론과 서술의 분리**: 위험점수/등급/우선순위/도달가능성/신뢰도는 전부
  `app/agent/risk_scoring.py`의 고정 규칙으로 계산한다(`SCORING_VERSION`으로 버전 추적).
  LLM은 이 계산된 사실을 벗어나 새로운 판정을 하지 않는다.
- **데이터 충돌 격리**: `app/agent/validation.py`가 finding 단위로 정합성을 검증해
  CONFLICT/REVIEW_REQUIRED로 판정하면, 그 finding이 속한 조치 그룹은 정상 그룹에서 완전히
  분리해 별도 섹션으로 보고한다.
- **환각 방지**: 프롬프트(`app/agent/prompts.py`)에 그룹별 `allowed_claims`/`forbidden_claims`를
  구조화해서 전달하고, 렌더링 직전 `app/agent/report_qa.py`가 금지 표현·소속 아닌 CVE 언급·
  근거 없는 위협 행위자 귀속·번역 누락(영어 잔존) 등을 정규식/구조 검사로 다시 한번 걸러낸다.
- **RAG는 배경 정보일 뿐**: Qdrant에서 검색된 CTI 문서는 "이 CVE가 실제로 악용됐다는 증거"가
  아니라 참고 배경으로만 취급하도록 프롬프트와 QA 검사 양쪽에서 강제한다.

전체 프롬프트 원문은 [`PROMPTS.md`](./PROMPTS.md)에 정리되어 있습니다.

## 프로젝트 구조

```
app/
├── main.py                 FastAPI 앱
├── config.py                환경변수 설정(Settings)
├── api/jobs.py               작업 생성/조회/보고서 다운로드 API
├── workers/                  Celery 앱, 태스크
├── database/                 Postgres(jobs) ORM 모델/세션
├── repositories/              MySQL 쿼리 실행 래퍼
├── queries/get_data.py       MySQL 조회 SQL 모음
├── services/data_processing_services.py  수집 데이터 가공(그룹화·점수·신뢰도 계산)
├── schemas/                  Pydantic 모델(API, LLM 출력 스키마)
└── agent/
    ├── graph.py                LangGraph 조립
    ├── nodes.py                 5단계 파이프라인 노드
    ├── state.py                  파이프라인 State 정의
    ├── risk_scoring.py           위험점수/우선순위/신뢰도 상수·규칙
    ├── validation.py              finding 데이터 정합성 검증
    ├── prompts.py                 LLM 프롬프트
    ├── llm_api.py                  LLM 클라이언트(분석용/번역용)
    ├── llm_json.py                  LLM JSON 응답 파싱/재시도
    ├── translate.py                 영→한 번역(그룹 단위 호출)
    ├── rag.py                        Qdrant CTI 벡터 검색
    ├── report_qa.py                  PDF 렌더링 전 자체 검증 게이트
    └── templates/report.html.jinja    보고서 HTML 템플릿

tests/          pytest 단위 테스트(LLM/DB 호출 없이 결정론적 로직 검증)
CTI_reports/    RAG 벡터DB 원본 CTI 문서(용량이 커서 git 제외, 별도 보관)
make_vectorDB.ipynb   CTI_reports/ -> Qdrant 컬렉션 구축 노트북
PROMPTS.md      전체 LLM 프롬프트 참고 문서
```

## 요구사항

- Python 3.13
- Postgres (작업 상태 저장용)
- RabbitMQ (Celery 브로커)
- MySQL (별도 수집 에이전트가 미리 채워둔 취약점 데이터, 읽기 전용 — 이 저장소에는
  수집기 코드가 포함되어 있지 않습니다)
- 아래 3개의 OpenAI 호환 API 서버 (llama.cpp 등으로 자체 서빙)
  - 사이버보안 분석용 LLM
  - translategemma (영→한 번역)
  - bge-m3 임베딩 서버
- Qdrant (RAG용 벡터DB, `Cyber-Threat-Intelligence` 컬렉션)

## 설치 및 실행

### 1. 의존성 설치

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

PDF 렌더링(WeasyPrint)에는 시스템 라이브러리와 한글 폰트가 필요합니다(Debian/Ubuntu 기준,
`Dockerfile` 참고):

```bash
sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
    libgdk-pixbuf2.0-0 libffi-dev shared-mime-info fonts-noto-cjk
```

### 2. 환경변수 설정

```bash
cp .env.example .env
```

`.env`를 열어 Postgres/RabbitMQ/MySQL 접속정보와 LLM/임베딩/Qdrant 엔드포인트를 채웁니다.
`.env`는 실제 비밀번호가 들어가므로 `.gitignore`에 의해 커밋되지 않습니다.

### 3. Postgres 테이블 생성

작업(Job) 상태를 저장할 테이블을 최초 1회 생성합니다.

```bash
python create_table.py
```

MySQL 쪽은 별도 수집 에이전트가 관리하는 기존 스키마를 그대로 읽기만 하므로 이 저장소에서
따로 만들 테이블이 없습니다(필요한 테이블 목록은 `app/queries/get_data.py` 참고).

### 4. API 서버 실행

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 5. Celery 워커 실행

```bash
celery -A app.workers.celery_app worker -l info --without-mingle --without-gossip
```

`--without-mingle --without-gossip`이 필요한 이유: 이 프로젝트가 쓰는 RabbitMQ 설정에서
Celery 기본 mingle/gossip 기능이 쓰는 큐 옵션을 거부해 워커가 크래시 루프에 빠지는 것을
실측으로 확인했습니다. 재시작 중복 실행 방지(`worker_pool='prefork'`, 하트비트 30초)는
`app/workers/celery_app.py`에 이미 반영되어 있습니다.

### 6. 동작 확인

```bash
# 작업 생성
curl -X POST http://localhost:8000/jobs/ \
  -H 'Content-Type: application/json' \
  -d '{"host_uuid": "<MySQL tb_host.host_uuid>"}'

# 상태 조회 (PENDING -> PROCESSING -> SUCCESS/FAILED)
curl http://localhost:8000/jobs/{job_id}

# 완료 후 PDF 다운로드
curl -OJ http://localhost:8000/jobs/{job_id}/report
```

생성된 PDF는 `reports/job_{job_id}.pdf`에도 저장됩니다.

### Docker로 API 서버만 실행

```bash
docker build -t vulnagent-api .
docker run --env-file .env -p 8000:8000 -v $(pwd)/reports:/app/reports vulnagent-api
```

`Dockerfile`은 API 서버(uvicorn) 기준입니다. Celery 워커도 같은 이미지로 CMD만
`celery -A app.workers.celery_app worker -l info --without-mingle --without-gossip`로 바꿔
띄우면 됩니다. Postgres/RabbitMQ/MySQL/LLM/Qdrant는 별도로 구동돼 있어야 합니다.

## RAG 벡터DB 구축 (선택)

CTI(위협 인텔리전스) 배경지식 검색을 쓰려면 `CTI_reports/`의 APT/위협 행위자 보고서 PDF들을
`make_vectorDB.ipynb`로 임베딩해 Qdrant `Cyber-Threat-Intelligence` 컬렉션(bge-m3, 1024차원)에
넣어야 합니다. 이 저장소에는 `CTI_reports/`가 포함되어 있지 않습니다(용량이 커서 `.gitignore`
처리). Qdrant/임베딩 서버가 응답하지 않아도 파이프라인은 CTI 맥락 없이 정상 동작합니다.

## 테스트

```bash
pytest tests/
```

LLM/실DB 호출 없이 결정론적 로직(위험점수, 우선순위 티어, 데이터 검증, CCE 정규화, 재시작
판정, 신뢰도 계산, 번역 폴백, report_qa 검증)을 단위 테스트로 검증합니다. 실 DB(MySQL)를 쓰는
회귀 테스트(`tests/test_regression_pipeline.py`)는 MySQL에 접속할 수 없으면 자동으로 skip됩니다.

## 주의사항

- `.env`, `CTI_reports/`, `reports/*.pdf`, `tb_*.json`, `table_BOM.xlsx`는 `.gitignore`에
  포함되어 있습니다. 실수로 강제 추가(`git add -f`)하지 않도록 주의하세요.
- MySQL의 취약점 데이터는 이 저장소가 아닌 별도 수집 에이전트가 채워넣습니다 — 이 서비스는
  읽기 전용으로만 접근합니다.
