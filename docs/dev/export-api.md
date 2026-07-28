# Export API — 스캔 취약점 결과 내보내기

외부 시스템(예: Python AI 보고서 생성기)이 스캔 결과를 JSON/XML 로 가져가는 읽기 전용 API.

- **엔드포인트**: `GET /export.php`
- **인증**: 헤더 `X-API-Token: <토큰>` (또는 `Authorization: Bearer <토큰>`). ingest(쓰기) 토큰과 분리된 전용 읽기 토큰.
- **토큰 발급**: 웹 관리자 메뉴 **연동 → API 토큰**(`/api-tokens.php`, admin 전용)에서 발급한다.
  발급 시 원문을 **한 번만** 보여준다(DB 엔 SHA-256 해시만 저장). 잃어버리면 새로 발급.
  더 안 쓰는 토큰은 같은 화면에서 **폐기**하면 즉시 무효가 된다.

## 파라미터

| 이름 | 값 | 기본 | 설명 |
|---|---|---|---|
| `format` | `json` \| `xml` | `json` | 응답 형식 |
| `host` | FQDN | — | 이 호스트만 |
| `scan_id` | 정수 | — | 특정 스캔만(지정 시 최신-스캔 규칙 무시) |
| `severity` | `critical,high,…` | 전체 | 쉼표 구분 심각도 필터 |
| `kev` | `1` | — | KEV(실제 악용) 등재 CVE 만 |
| `min_epss` | 0.0~1.0 | — | EPSS(악용확률) 하한 |

스코프 기본값: **호스트별 최신 스캔**의 findings.

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
          "summary": "OpenSSL heap overflow …"
        }
      ]
    }
  ]
}
```

XML 은 같은 구조를 요소로 표현한다: `<vulnExport><summary><bySeverity/></summary><hosts><host><findings><finding>…`.
스칼라는 속성, 긴 텍스트(`rationale`·`summary`)는 자식 요소.

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
