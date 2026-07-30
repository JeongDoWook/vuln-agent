# secrets/

DB 비밀번호·수신 토큰을 담는 **Docker Secrets** 디렉토리.
여기의 `*.txt` 는 컨테이너의 `/run/secrets/*` 로 마운트되어 비밀값으로 쓰인다.

## 필요한 파일 (각 한 줄, 값만)

| 파일 | 용도 |
|---|---|
| `mysql_root_password.txt` | MySQL root 비밀번호 |
| `mysql_password.txt`      | 앱 DB 유저(`vulnagent`) 비밀번호 |
| `rematch_token.txt`       | 재매칭 관리 API 인증 토큰 |
| `admin_password.txt`      | 웹 최초 관리자(admin) 비밀번호 (users 비었을 때 부트스트랩) |
| `duckdns_token.txt`       | **prod 전용** — Caddy 가 Let's Encrypt DNS-01 로 인증서를 받을 때 쓰는 DuckDNS 계정 토큰 (랜덤 생성 아님, 본인 계정 값) |

> Export API 토큰은 여기 두지 않는다 — 웹(`/api-tokens.php`)에서 발급하고 DB 에 해시로만 저장한다.

## 생성

`deploy/compose_runner.sh init` (러너는 `deploy/` 에 있음)이 위 파일들을 이 `secrets/`(루트 유지)에
**강한 랜덤값으로 자동 생성**한다(이미 있으면 유지). 수동 생성 예(저장소 루트에서):

```bash
openssl rand -base64 24 | tr -d '\n' > secrets/mysql_root_password.txt
openssl rand -base64 24 | tr -d '\n' > secrets/mysql_password.txt
openssl rand -base64 24 | tr -d '\n' > secrets/rematch_token.txt
```

## 주의
- `*.txt` 는 **절대 git 에 커밋하지 않는다**(.gitignore). 이 README 만 커밋된다.
- 에이전트 수집 토큰은 웹의 **에이전트 키** 화면에서 호스트별로 발급하며 이 디렉터리에 저장하지 않는다.
- `rematch_token.txt`는 재매칭 관리 API 전용이며 에이전트 수집에 사용할 수 없다.
- 끝에 개행이 들어가지 않도록 주의(위 예시의 `tr -d '\n'`).
