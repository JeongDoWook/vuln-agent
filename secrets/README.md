# secrets/

DB 비밀번호·수신 토큰을 담는 **Docker Secrets** 디렉토리.
여기의 `*.txt` 는 컨테이너의 `/run/secrets/*` 로 마운트되어 비밀값으로 쓰인다.

## 필요한 파일 (각 한 줄, 값만)

| 파일 | 용도 |
|---|---|
| `mysql_root_password.txt` | MySQL root 비밀번호 |
| `mysql_password.txt`      | 앱 DB 유저(`vulnagent`) 비밀번호 |
| `ingest_token.txt`        | 에이전트↔서버 공유 인증 토큰 (에이전트 `--token` 값) |
| `admin_password.txt`      | 웹 최초 관리자(admin) 비밀번호 (users 비었을 때 부트스트랩) |

## 생성

`./compose_runner.sh init` 이 위 파일들을 **강한 랜덤값으로 자동 생성**한다(이미 있으면 유지).
수동 생성 예:

```bash
openssl rand -base64 24 | tr -d '\n' > secrets/mysql_root_password.txt
openssl rand -base64 24 | tr -d '\n' > secrets/mysql_password.txt
openssl rand -base64 24 | tr -d '\n' > secrets/ingest_token.txt
```

## 주의
- `*.txt` 는 **절대 git 에 커밋하지 않는다**(.gitignore). 이 README 만 커밋된다.
- 에이전트에서 전송할 때 `--token` 값은 `ingest_token.txt` 내용과 동일해야 한다.
- 끝에 개행이 들어가지 않도록 주의(위 예시의 `tr -d '\n'`).
