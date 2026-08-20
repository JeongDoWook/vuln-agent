# Export API — 스캔 취약점 결과 내보내기

> 문서 기준: 2026-08-20.

외부 시스템(예: Python AI 보고서 생성기)이 스캔 결과를 JSON/XML 로 가져가는 읽기 전용 API — `export.php` 는
**취약점 판정 결과**만 내보낸다. 부품표는 형제 엔드포인트 `GET /sbom.php`(CycloneDX 1.5 / SPDX 2.3, 아래 §SBOM).

- **엔드포인트**: `GET /export.php`
- **인증**: **웹 로그인 세션**(자산 메뉴 권한 — `vg_require_menu('assets')`). 전용 API 토큰은 2026-08-13 폐지.
- **부르는 법**: 웹에 로그인한 브라우저에서 URL 을 그대로 연다. 스크립트로 받을 때는 로그인 세션 쿠키를 함께 보낸다.

**응답 실패**는 전부 JSON 이다(`format=xml` 이어도) — `{"ok":false,"error":…,"code":…,"ts":…}`. `code` 는
`method_not_allowed`(405, GET/HEAD 외) · `internal_error`(500). 인증 실패만은 화면과 같은 게이트라 JSON 이
아니라 미로그인 302(`/login.php`) · 권한 없음 403 이다. 예외 원문은 응답에 싣지 않는다.

**감사 로그**: 호출 1회마다 누가·언제·어떤 필터로·몇 건을 가져갔는지 `tb_activity_log` 에 남는다
(`activity_type=export_data`, `action=EXPORT`, `host` 지정이 없으면 "전체 호스트"). 기록에 실패해도 다운로드는 막지 않는다.

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

`remediation_*` 3필드는 사람이 남긴 **미조치 사유 메모**다(없으면 전부 `null`). 이 제품은 조치 워크플로를 갖지 않는다 — 본격 워크플로는 이 API 를 가져가는 외부 시스템 몫이다.

XML 은 같은 구조를 요소로 표현한다: `<vulnExport><summary><bySeverity/></summary><hosts><host><findings><finding>…`.
스칼라는 속성, 긴 텍스트(`rationale`·`summary`·`remediationReason`)는 자식 요소.

## Python 예시

```python
import re, requests

BASE = "https://<운영-도메인>:8080"   # 이 배포의 중앙서버 주소(포트는 WEB_PORT)

# 로그인 폼의 CSRF 토큰을 받아 같은 세션으로 POST — 이후 요청은 그 세션 쿠키로 인증된다.
s = requests.Session()
form = s.get(f"{BASE}/login.php", timeout=30).text
csrf = re.search(r'name="csrf" value="([^"]+)"', form).group(1)
s.post(f"{BASE}/login.php", data={"csrf": csrf, "username": USER, "password": PASSWORD}, timeout=30)

r = s.get(f"{BASE}/export.php", params={"format": "json", "severity": "critical,high"}, timeout=30)
r.raise_for_status()
data = r.json()
```

설치 패키지 전체 목록은 포함하지 않는다(호스트당 수천 건 → 보고서엔 노이즈) — 취약점 결과와 호스트 맥락뿐이다.

## SBOM — `GET /sbom.php`

인증·감사·실패 응답은 `export.php` 와 같다. 다른 점은 **대상 하나당 문서 하나**라는 것뿐이다 —
`host` 또는 `scan_id` 를 반드시 준다(없으면 400 `target_required`).

| 이름 | 값 | 기본 | 설명 |
|---|---|---|---|
| `format` | `cyclonedx` \| `spdx` | `cyclonedx` | 문서 표준. 그 밖의 값은 기본값으로 떨어진다 |
| `host` | FQDN | — | `scan_id` 가 없으면 이 호스트의 **최신 스캔** |
| `scan_id` | 정수 | — | 그 스캔 하나 |
| `cid` | 컨테이너 cid 문자열 | — | 그 컨테이너 하나의 부품표. 안 주면 호스트 자신 |
| `view` | `html` | — | **시각화 보기**(아래) |
| `page` · `per_page` | 정수 | 목록 기본값 | `view=html` 의 컴포넌트 표 페이지네이션 |

`cid` 가 숫자 `container_id` 가 아닌 것은 의도다 — 숫자 id 는 스캔마다 새로 발급돼 북마크·스크립트가 다음
수집에서 깨진다. 의존 엣지(dependencies/relationships)는 넣지 않고, 같은 스캔·같은 범위면 `serialNumber` 가
항상 같다(결정적 UUIDv5 — 파일로 보관하고 diff 할 수 있게).

### 시각화 보기 (`view=html`)

`view=html` 이면 파일을 내려받는 대신 **화면을 그린다** — 컴포넌트 수·패키지 관리자 수·카피레프트/미상
라이선스 KPI, 생태계 분포, 관리자별 컴포넌트 표다. 이 파라미터가 없을 때의 기본 계약(파일 다운로드)은
그대로다. 감사로그는 갈린다 — 다운로드 `export_sbom`, 시각화 보기 `view_sbom`(둘 다 `action=EXPORT`).
`view_sbom` 은 **GET 일 때만** 남긴다(HEAD 는 프리페치로 실제 열람 없이 걸릴 수 있다).
