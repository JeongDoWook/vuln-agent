# UI 운영 설정

UI 목록 크기와 요약 카드 한도는 코드 수정 없이 웹 컨테이너 환경변수로 조정한다.
값이 없거나 허용 범위를 벗어나면 안전한 기본값을 사용한다.

| 환경변수 | 기본값 | 허용 범위 | 용도 |
|---|---:|---:|---|
| `UI_PER_PAGE_OPTIONS` | `10,20,40,60,100` | 각 5~200 | 목록의 페이지 크기 선택지 |
| `UI_PER_PAGE_DEFAULT` | `20` | 선택지 중 하나 | 기본 페이지 크기 |
| `UI_DASHBOARD_URGENT_LIMIT` | `6` | 3~30 | 대시보드 대응 우선순위 |
| UI_DASHBOARD_ACTIONABLE_STATUSES | EXTERNAL,LAN,LISTENING,RUNNING,LOADED | 허용 상태값 | KEV 긴급 목록에 포함할 실제 사용 상태 |
| `UI_DETAIL_PREVIEW_LIMIT` | `10` | 5~100 | 상세 화면 이력·프로세스 미리보기 |
| `UI_TREND_LIMIT` | `50` | 10~500 | 상세 화면 추이 데이터 수 |
| `AUDIT_PAGE_VIEWS` | `1` | boolean | 인증된 HTML 페이지 열람 로그 |

예시는 `deploy/compose.yml`의 웹 서비스 `environment`에 추가한다.

```yaml
environment:
  UI_PER_PAGE_DEFAULT: "20"
  UI_DASHBOARD_URGENT_LIMIT: "8"
  AUDIT_PAGE_VIEWS: "1"
```

페이지 열람 로그에는 페이지명·메뉴 코드·검색 쿼리의 키만 저장하고 값은 저장하지 않는다.
공통 감사 모듈은 password/token/secret/csrf/authorization 계열 필드를 재귀적으로 마스킹한다.