# Export API — 스캔 취약점 결과 내보내기

> 문서 기준: 2026-08-15.

외부 시스템(예: Python AI 보고서 생성기)이 스캔 결과를 JSON/XML 로 가져가는 읽기 전용 API.

> **부품표(SBOM)는 형제 엔드포인트가 따로 있다** — `GET /sbom.php`(CycloneDX 1.5 / SPDX 2.3).
> 인증이 같고 자산 하나당 문서 하나를 낸다(`host` 또는 `scan_id` 필수).
> 이 문서가 다루는 `export.php` 는 **취약점 판정 결과**만 내보낸다.

- **엔드포인트**: `GET /export.php`
- **인증**: **웹 로그인 세션**(자산 메뉴 권한 — `vg_require_menu('assets')`). 전용 API 토큰 체계는
  폐지했다(2026-08-13) — 결과를 가져가는 쪽이 DB 를 직접 조회하기로 해서 토큰을 유지할 이유가
  없어졌다. `/api-tokens.php` 화면과 `tb_api_token` 테이블도 함께 없앴다.
- **부르는 법**: 웹에 로그인한 브라우저에서 URL 을 그대로 연다. 스크립트로 받을 때는 로그인
  세션 쿠키를 함께 보낸다. 미로그인 요청은 다른 화면과 똑같이 `/login.php` 로 리다이렉트되고,
  로그인은 됐지만 자산 메뉴 권한이 없으면 403 이다.

**응답 실패**는 전부 JSON 이다(`format=xml` 이어도) — `{"ok":false,"error":…,"code":…,"ts":…}`.
`code` 는 `method_not_allowed`(405, GET/HEAD 외) · `internal_error`(500). 인증 실패는 JSON 이 아니라
로그인 리다이렉트(302)이거나 403 이다 — 화면과 같은 게이트를 쓰기 때문이다. 예외 원문은 응답에 싣지 않고 서버 로그로만 남긴다.

**감사 로그**: 호출 1회마다 누가(로그인 사용자)·언제·어떤 필터로·몇 건을 가져갔는지 `tb_activity_log` 에
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
import re
import requests

# BASE 는 이 배포의 중앙서버 주소(운영 배포 시 정한 `<운영-도메인>`, 포트는 WEB_PORT).
BASE = "https://<운영-도메인>:8080"

# 웹 로그인 세션으로 인증한다 — 로그인 폼의 CSRF 토큰을 먼저 받아 같은 세션으로 POST 한다.
s = requests.Session()
form = s.get(f"{BASE}/login.php", timeout=30).text
csrf = re.search(r'name="csrf" value="([^"]+)"', form).group(1)
s.post(f"{BASE}/login.php",
       data={"csrf": csrf, "username": USER, "password": PASSWORD}, timeout=30)

r = s.get(
    f"{BASE}/export.php",
    params={"format": "json", "severity": "critical,high"},
    timeout=30,
)
r.raise_for_status()
data = r.json()
for host in data["hosts"]:
    for f in host["findings"]:
        ...  # AI 보고서 입력으로 사용
```

설치 패키지 전체 목록은 포함하지 않는다(호스트당 수천 건 → 보고서엔 노이즈). 취약점 결과와 호스트 맥락만 내보낸다.
