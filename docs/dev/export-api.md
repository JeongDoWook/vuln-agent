# Export API — 스캔 취약점 결과 내보내기

> 문서 기준: 2026-08-09.

외부 시스템(예: Python AI 보고서 생성기)이 스캔 결과를 JSON/XML 로 가져가는 읽기 전용 API.

- **엔드포인트**: `GET /export.php`
- **인증**: 헤더 `X-API-Token: <토큰>` (또는 `Authorization: Bearer <토큰>`). ingest(쓰기) 토큰과 분리된 전용 읽기 토큰.
- **토큰 발급**: 웹 관리자 메뉴 **관리 → API 키**(`/api-tokens.php`, admin 전용)에서 발급한다.
  발급 시 원문을 **한 번만** 보여준다(DB 엔 SHA-256 해시만 저장). 잃어버리면 새로 발급.
  더 안 쓰는 토큰은 같은 화면에서 **폐기**하면 즉시 무효가 된다.
- **유효기간**: 발급 시 무기한/30일/90일/1년 중에서 고른다. 기간이 지난 토큰은 인증이 **401 로
  거부**되고 `api_token_expired` 감사로그가 남는다. 자동 갱신·재발급은 없으므로 만료 전에 새 토큰을
  발급해 교체한다(목록에 만료 7일 전부터 '만료 임박'으로 표시된다). 기존에 발급된 무기한 토큰은
  그대로 계속 동작한다.

**응답 실패**는 전부 JSON 이다(`format=xml` 이어도) — `{"ok":false,"error":…,"code":…,"ts":…}`.
`code` 는 `method_not_allowed`(405, GET/HEAD 외) · `unauthorized`(401, 토큰 없음·폐기·만료) ·
`internal_error`(500). 예외 원문은 응답에 싣지 않고 서버 로그로만 남긴다.

**감사 로그**: 호출 1회마다 누가(토큰)·언제·어떤 필터로·몇 건을 가져갔는지 `tb_activity_log` 에
남는다(`activity_type=export_data`, `action=EXPORT`, 처리 대상은 `host` 지정이 없으면 "전체 호스트").
감사 기록에 실패해도 다운로드는 막지 않는다.

## 파라미터

| 이름 | 값 | 기본 | 설명 |
|---|---|---|---|
| `format` | `json` \| `xml` | `json` | 응답 형식 |
| `host` | FQDN | — | 이 호스트만 |
| `scan_id` | 정수 | — | 특정 스캔만(지정 시 최신-스캔 규칙 무시) |
| `severity` | `critical,high,…` | 전체 | 쉼표 구분 심각도 필터 |
| `kev` | `1` | — | KEV(실제 악용) 등재 CVE 만 |
| `min_epss` | 0.0~1.0 | — | EPSS(악용확률) 하한 |

스코프 기본값: **호스트별 최신 스캔**의 findings. `scan_id` 를 주면 그 스캔 하나만 보므로 `host`
필터는 무시된다. `severity` 는 `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` 만 인정하고 그 밖의 값은 버린다.
정렬은 심각도 → EPSS 내림차순 → CVE ID 순이다.

## 응답 구조 (JSON)

```json
{
  "ok": true,
  "generated_at": "2026-07-12T20:49:24+09:00",
  "summary": {
    "hosts": 1, "findings": 4, "kev": 2, "exposed": 2,
    "by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1}
  },
  "hosts": [
    {
      "fqdn": "web01.example.com",
      "os_id": "ubuntu", "os_version": "24.04",
      "kernel": "6.8.0-31-generic", "agent_version": null,
      "scan_id": 1, "collected_at": "2026-07-12 20:49:03", "package_count": 742,
      "findings": [
        {
          "cve": "CVE-2026-99001",
          "package": "openssl", "installed_version": "3.0.13-0ubuntu3.4",
          "severity": "CRITICAL", "cvss": 9.8,
          "epss": 0.84213, "epss_percentile": 0.99231,
          "kev": true, "loaded": true, "exposed": true, "exposure_scope": "EXTERNAL",
          "fixed_version": "3.0.13-0ubuntu3.6",
          "rationale": "…왜 이 등급인지…",
          "summary": "OpenSSL heap overflow …",
          "remediation_reason": "내부망 전용이고 벤더 수정본이 없어 다음 정기점검까지 보류",
          "remediation_approved_by": "admin",
          "remediation_approved_at": "2026-08-08 11:25:25"
        }
      ]
    }
  ]
}
```

`remediation_*` 3필드는 사람이 남긴 **미조치 사유 메모**다(없으면 전부 `null`).
이 제품은 결재선·상태 전이 같은 조치 워크플로를 갖지 않는다 — "왜 지금 고치지 않는가"와
"누가 언제 그렇게 판단했는가"만 붙들고, 본격 워크플로는 이 API 를 가져가는 외부 시스템의 몫이다.

XML 은 같은 구조를 요소로 표현한다: `<vulnExport><summary><bySeverity/></summary><hosts><host><findings><finding>…`.
스칼라는 속성, 긴 텍스트(`rationale`·`summary`·`remediationReason`)는 자식 요소.

## Python 예시

```python
import requests

# BASE 는 이 배포의 중앙서버 주소(운영 배포 시 정한 `<운영-도메인>`, 포트는 WEB_PORT).
BASE = "https://<운영-도메인>:8080"

r = requests.get(
    f"{BASE}/export.php",
    params={"format": "json", "severity": "critical,high"},
    headers={"X-API-Token": EXPORT_TOKEN},
    timeout=30,
)
r.raise_for_status()
data = r.json()
for host in data["hosts"]:
    for f in host["findings"]:
        ...  # AI 보고서 입력으로 사용
```

설치 패키지 전체 목록은 포함하지 않는다(호스트당 수천 건 → 보고서엔 노이즈). 취약점 결과와 호스트 맥락만 내보낸다.
