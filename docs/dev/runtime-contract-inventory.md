# 런타임 HTTP 계약 인벤토리

기준일: 2026-08-15. 기계 판독 정본은 `tests/fixtures/route-query-contract.json`이고,
`php tests/route_query_contract_test.php`가 `server/public/*.php` 전수, query key, 인증 가드,
응답 유형과 redirect를 정적으로 대조한다. 아래 `unknown`은 미사용 판정이 아니라 저장소 밖
소비자를 확인하지 못했다는 뜻이다.

## Public route

| route | method | auth | accepted query | redirect | response | in-repo caller / external class |
|---|---|---|---|---|---|---|
| `/activity.php` | GET | activity | action, from, ip, page, per_page, q, scope, to, user | - | HTML | nav / bookmark |
| `/advisories.php` | GET | advisories | page, per_page, q, scope | - | HTML | nav / bookmark |
| `/advisory.php` | GET | advisories | id, cpage, cper_page, apage, aper_page | - | HTML | advisories / bookmark |
| `/agent-command-overview.php` | GET | assets | - | - | JSON | app.js / unknown |
| `/agent-command-status.php` | GET | assets | id | - | JSON | host / unknown |
| `/agent-dl.php` | GET | public | f | - | download | agent-tokens, assets / installer, CLI |
| `/agent-poll.php` | GET | agent token | - | - | JSON | install-agent / installed agent |
| `/agent-progress.php` | POST | agent token | - | - | JSON | inventory-agent / installed agent |
| `/agent-tokens.php` | GET, POST | agenttokens | fqdn, page, per_page, q | - | HTML | nav, assets / bookmark |
| `/asset-packages.php` | GET | assets | host, manager, page, per_page, q | - | HTML | assets / bookmark |
| `/assets.php` | GET, POST | assets | dept, grade, page, per_page, q, state | - | HTML | nav, dashboard / bookmark |
| `/cce-rule.php` | GET | catalog or compliance or findings | code, page, per_page | - | HTML | cce-rules, host / bookmark |
| `/cce-rules.php` | GET | catalog | page, per_page, q, sev | - | HTML | nav / bookmark |
| `/changes.php` | GET | findings | host, page, per_page, q, tab, type, window | - | HTML | nav, host / bookmark |
| `/compliance.php` | GET | compliance | - | - | HTML | nav / bookmark |
| `/compliance_rule.php` | GET | catalog or compliance or findings | page, per_page, rule | - | HTML | compliance-rules, host / bookmark |
| `/compliance_rules.php` | GET | catalog | page, per_page, q, sev | - | HTML | nav / bookmark |
| `/connectors.php` | GET, POST | connectors | conn, edit, page, per_page | - | HTML | nav / bookmark |
| `/container.php` | GET | assets or findings | cid, epage, id, page, per_page, q, tab | - | HTML | host, findings / bookmark |
| `/control.php` | GET | compliance or findings | control, fw, page, per_page | - | HTML | control_mapping / bookmark |
| `/control_mapping.php` | GET | compliance | control, fw, page, per_page | `control` → `/control.php?fw=…&control=…` (302) | HTML | nav / legacy bookmark |
| `/cve.php` | GET | findings or catalog or advisories | cve, page/per_page, vpage/vper_page, apage/aper_page | - | HTML | findings, cves / bookmark |
| `/cves.php` | GET | catalog | epss, kev, page, per_page, q, sev, sort, year | - | HTML | nav / bookmark |
| `/depgraph.php` | GET | assets or findings | cid, id, mgr, name, tab, ver | - | HTML | host, container / bookmark |
| `/export.php` | GET, HEAD | assets | format, host, kev, min_epss, scan_id, severity | - | JSON/XML download | assets, host / reporting client |
| `/feed_preview.php` | GET, POST | connectors | type + connector catalog fields | - | JSON | connectors.js / unknown |
| `/finding_history.php` | GET, POST | findings | cid, cve, id, page, per_page, pkg | - | HTML | findings, host / bookmark |
| `/findings.php` | GET | findings | ctr, fst, fx, host, page, per_page, q, res, scan_id, scope, sev, sort, st, type | - | HTML | nav, dashboard / bookmark |
| `/host.php` | GET, POST | assets or findings | acc, epage, id, page, per_page, q, tab | `tab=resources` → `tab=scans` (302); delete → `/assets.php` (303) | HTML | assets, findings / bookmark |
| `/index.php` | GET | dashboard | page, per_page | - | HTML | nav / browser root |
| `/ingest.php` | POST | agent token | - | - | JSON | install-agent, inventory-agent, agent_push / installed agent, CLI |
| `/language-packages.php` | GET | public | all keys passthrough | `/packages.php?tab=lang` + original query (302) | redirect | none / legacy bookmark |
| `/login.php` | GET, POST | public | kind, reason | authenticated/success → `/` (302) | HTML | auth / bookmark |
| `/logout.php` | GET | session | - | `/login.php` (302) | redirect | nav / bookmark |
| `/nofix-packages.php` | GET | findings | host, page, per_page, q | - | HTML | findings / bookmark |
| `/package.php` | GET | catalog or findings | eco, name, page, per_page | - | HTML | packages, findings / bookmark |
| `/packages.php` | GET | catalog | eco, manager, page, per_page, q, risk, sort, tab | - | HTML | nav, language redirect / bookmark |
| `/permissions.php` | GET, POST | permissions | - | - | HTML | nav / bookmark |
| `/profile.php` | GET, POST | login | - | - | HTML | nav / bookmark |
| `/sbom.php` | GET, HEAD | assets | cid, format, host, scan_id | - | JSON download | host, container / SBOM client |
| `/settings.php` | GET, POST | settings | - | - | HTML | nav / bookmark |
| `/styleguide.php` | GET | dashboard | - | - | HTML | none / unknown |
| `/user.php` | GET, POST | users | id | delete → `/users.php` (302) | HTML | users / bookmark |
| `/users.php` | GET, POST | users | page, per_page, q, role | - | HTML | nav / bookmark |
| `/vendor.php` | GET | catalog | page, per_page, q, rel, src | - | HTML | cve, package / bookmark |

`auth`는 기존 session menu guard를 뜻한다. `agent token`은 `X-Agent-Token`을 우선하고
기존 `Authorization: Bearer`도 허용한다. `public`은 네트워크 공개가 안전하다는 평가가 아니라
해당 entrypoint 자체에 session/menu guard가 없다는 현재 사실이다.

## 에이전트 소비 계약

| flow | request | success response consumed by current agent | failures/status |
|---|---|---|---|
| install | `--server`, `--token`; server를 `/ingest.php`로 보정 | poll URL을 같은 base의 `/agent-poll.php`로 파생 | curl/wget 타임아웃과 실패 종료 유지 |
| poll | GET + agent token | `poll_schedule_seconds`, `due_command_id`, `cpu_quota_percent`, `packaging_timeout_seconds`, `mem_max_mb` | 401, 405 |
| progress | POST form: `command_id`, `stage`, `percent`, `message`, `state` | `ok`, `cancel_requested`; state는 running/failed/cancelled | 401, 404, 405, 409, 422 |
| ingest | POST JSON + token/timestamp/nonce; 최소 `meta`, `pkg`, optional `command_id` | `ok`, host/scan IDs, counts, changed, integrity, findings, CCE, accounts | 400, 401, 403, 405, 409, 500 |

저장소 내부 CLI/cron 소비자는 `agent/install-agent.sh`, `agent/vuln-inventory-agent.sh`,
`deploy/agent_push.sh`, `deploy/agent_schedule.sh`이다. 이미 설치된 에이전트, 저장된 북마크,
보고서/SBOM 클라이언트는 저장소 밖 소비자이므로 존재를 배제할 수 없다. 따라서 agent API는
기존 필드·상태를 보존하는 additive-only이고, 호환 redirect는 관측 증거 없이 삭제하지 않는다.
