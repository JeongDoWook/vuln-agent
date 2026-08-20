# secrets/

> 문서 기준: 2026-08-20. 비밀값 원문은 Git에 커밋하지 않는다.

DB 비밀번호 등 배포 비밀값을 담는 **Docker Secrets** 디렉토리.
여기의 `*.txt` 는 컨테이너의 `/run/secrets/*` 로 마운트되어 비밀값으로 쓰인다.

## 필요한 파일 (각 한 줄, 값만)

| 파일 | 용도 |
|---|---|
| `mysql_root_password.txt` | MySQL root 비밀번호 |
| `mysql_password.txt`      | 앱 DB 유저(`vulnagent`) 비밀번호 |
| `admin_password.txt`      | 웹 최초 관리자(admin) 비밀번호 (users 비었을 때 부트스트랩) |

> 이 셋이 전부다. Caddy 는 시크릿을 쓰지 않고(TLS 가 자체서명 `tls internal` 이라 외부 DNS
> 토큰이 필요 없다 — 2026-08-09 확정, `deploy/caddy/README.md`), Export·SBOM 은 웹 로그인
> 세션으로 인증한다. 남아 있는 `duckdns_token.txt` 는 지워도 되고, 폐지된 전용 API 토큰
> 파일은 만들지 않는다.

## 생성

`deploy/compose_runner.sh init` (러너는 `deploy/` 에 있음)이 위 파일들을 이 `secrets/`(루트 유지)에
**강한 랜덤값으로 자동 생성**한다(이미 있으면 유지). 수동 생성 예(저장소 루트에서):

```bash
openssl rand -base64 24 | tr -d '\n' > secrets/mysql_root_password.txt
openssl rand -base64 24 | tr -d '\n' > secrets/mysql_password.txt
```

## 주의
- `*.txt` 는 **절대 git 에 커밋하지 않는다**(.gitignore). 이 README 만 커밋된다.
- 에이전트 수집 토큰은 웹의 **에이전트 키** 화면에서 호스트별로 발급하며 이 디렉터리에 저장하지 않는다.
- 끝에 개행이 들어가지 않도록 주의(위 예시의 `tr -d '\n'`).
