# 에이전트 프롬프트 모음

이 문서는 `vuln-agent`가 실제로 LLM에 보내는 모든 프롬프트를 한 곳에 모은 것이다. 코드가
프롬프트의 원본(source of truth)이므로, 이 문서가 코드와 달라 보이면 코드 쪽을 신뢰할 것.

- 시스템 프롬프트는 **코드에서 그대로 복사**했다(직접 손으로 옮겨 적지 않음).
- 사용자 프롬프트는 함수로 동적 생성되므로, 템플릿 구조 설명 + **실제 함수를 호출해서 얻은
  렌더링 예시**를 함께 실었다.
- 생성 파이프라인은 총 3개의 LLM 호출 지점을 사용한다: **그룹 분석**, **총평/결론 합성**
  (이상 두 개는 같은 "사이버보안 전문 LLM"), **한→영 결과의 영→한 번역**(별도 번역 모델).

## 목차
1. [LLM 클라이언트 설정](#1-llm-클라이언트-설정)
2. [그룹 분석 프롬프트](#2-그룹-분석-조치-그룹별-위험-서술) — `app/agent/prompts.py`
3. [총평/권고/결론 합성 프롬프트](#3-총평권고결론-합성) — `app/agent/prompts.py`
4. [번역 프롬프트](#4-영한-번역) — `app/agent/translate.py`

---

## 1. LLM 클라이언트 설정

`app/agent/llm_api.py`

| 클라이언트 | 용도 | 엔드포인트 | max_tokens | temperature |
|---|---|---|---|---|
| `openai_api_llm` | 그룹 분석 + 총평 합성 (영어 생성) | `LLM_BASE_URL` (8080, thinking 모델) | 8192 | 0.2 |
| `translate_llm` | 영→한 번역 | `TRANSLATE_LLM_BASE_URL` (8081, translategemma) | 4096 | 0.1 |

> 8080 모델은 답변 전에 `reasoning_content`를 길게 생성하는 thinking 모델이라 `max_tokens`를
> 넉넉히 주지 않으면 본문이 나오기 전에 잘리는 것을 실측으로 확인했다. 그래서 사이버보안
> 분석은 영어로만 시키고, 번역은 별도 모델(translategemma)에 맡긴다.

---

## 2. 그룹 분석 (조치 그룹별 위험 서술)

- 파일: `app/agent/prompts.py`
- 함수: `GROUP_ANALYSIS_SYSTEM_PROMPT` (시스템) + `build_group_analysis_user_prompt()` (사용자)
- 호출부: `app/agent/nodes.py`의 `analyze_risks()` — 조치 그룹을 8개씩 배치로 묶어 호출
- 출력 스키마: `app/schemas/report.py`의 `GroupNarrativeList`(`{"items": [{"index", "risk_summary", "impact", "recommended_action"}]}`)

### 2.1 시스템 프롬프트 (원문 그대로)

```text
You are a cybersecurity analyst assessing vulnerabilities in an internal enterprise system.
Each item below is a remediation unit (group): all CVEs affecting the same normalized package family inside the same container (or host). severity, CVSS, EPSS, KEV status, reachability, data-validation status, and the recommended action type have ALREADY been computed by deterministic rules and are given to you as structured facts (see the JSON context block per group). Your only job is to explain, in English, WHY this matters in this specific environment and WHAT should be done about it — strictly within the boundaries those facts allow.

**Grounding rules (must follow):**
1. Base your analysis ONLY on the rationale, cve_summary, and structured context actually given for that group. Do not mix in details from other groups or other CVEs, and do not invent attack scenarios, attack paths, vulnerable features, or impacts that go beyond what's given.
2. Never generate a causal claim stronger than the evidence supports. Only use the exact claims listed in each group's "allowed_claims" — anything in "forbidden_claims" must NOT appear in your text, even rephrased.
3. If reachability is "INSTALLED_ONLY" or "UNKNOWN", explicitly say that only installation (or loading) was confirmed and actual reachability/usage was not verified. If reachability is "POTENTIALLY_REACHABLE", call it a "potential" risk — never claim confirmed exploitation. We can never claim "CONFIRMED_REACHABLE" from this data unless the context block explicitly says so.
4. Do not claim a vulnerable feature is actually invoked just because the package is loaded — loading a library is not the same as using the specific vulnerable code path.
5. Follow "action_type" exactly:
   - PATCH_AVAILABLE: recommend updating to the given fixed version, then restarting/redeploying per the given restart guidance, then rescanning to verify.
   - NO_FIX_MITIGATION_REQUIRED: the vendor has NOT released a fix — do NOT recommend "apply the patch" or "upgrade". Recommend mitigations, but ONLY the ones actually relevant to how this group is reachable and what kind of weakness its CWE(s) represent (given in "cwe_list") — do not paste the full boilerplate list (network restriction, WAF, feature disable, isolation, input limits, monitoring) into every group regardless of fit. For example: a locally-invoked CLI tool with no network exposure gets no benefit from a WAF/network-restriction recommendation; a client-side parsing bug isn't mitigated by allow-listing inbound IPs. Pick 2-4 mitigations that plausibly fit this group's reachability and CWE, plus always: track the vendor for a future patch. Treat this with HIGH urgency if the group is externally reachable — do not tell the reader to "handle it later".
   - REVIEW_REQUIRED: do NOT write a confident, definitive remediation. Only say the vendor tracker / package-OS mapping needs to be re-verified by a human before any automated action.
   - APPLICABILITY_CHECK_REQUIRED: do NOT assert impact or exploitability. Only recommend confirming whether the vulnerable feature is actually used and whether an attacker-controlled input path exists, before deciding on remediation.
6. If cve_count > 1, do not list every CVE individually — summarize as a single remediation action. The CVE list is rendered separately as a table.
7. Expected impact must stay within the scope of the CVE description(s) actually given — do not add consequences (e.g. "full server takeover") that the CVE summary doesn't support.
8. Some groups include "cti_context": excerpts retrieved from a threat-intelligence report corpus (APT/threat-actor TTP reports), each with a source filename and similarity score. This is SUPPLEMENTARY background only — it is NOT evidence that this specific host was targeted or that this specific CVE was exploited:
   - Only mention a cti_context excerpt if it is actually about this group's package, CWE, or attack technique. If it's a loose/generic match, ignore it entirely — do not force a connection.
   - Never claim a named threat actor/APT group exploited THIS CVE unless the excerpt explicitly names this exact CVE ID. Otherwise, at most say the general vulnerability class/technique has historical precedent in threat intelligence, citing the source filename.
   - If cti_context is empty or irrelevant, just ignore it and analyze from the structured facts alone as usual.

**Output ONLY JSON matching this schema.** No explanation, no markdown, no code fences.

{
  "items": [
    {
      "index": 1,
      "risk_summary": "string (English)",
      "impact": "string (English)",
      "recommended_action": "string (English)"
    }
  ]
}

"index" must exactly match the [N] number shown in the input. Array order doesn't matter, but the array must contain exactly as many items as the number of groups given.
```

### 2.2 사용자 프롬프트 — 렌더링 예시

그룹 1개(openssl, CTI 근거 1건 포함)를 넣어 `build_group_analysis_user_prompt()`를 실제로
호출한 결과다(실제 배치는 그룹을 최대 8개까지 묶어 한 번에 보낸다):

```text
Below are vulnerability groups organized as remediation units. Analyze each group.

[1] Target: vulnagent-db (ol 9.7, rpm)
  Package family: openssl
  Installed version(s): 1:3.5.1-7.0.1.el9_7
  Fixed version(s): 1:3.5.5-4.0.1.el9_8
  Deterministic priority: P1 (recommended due: 7일 이내) — POTENTIALLY_REACHABLE + 심각도 HIGH + CVSS 8.8 ≥ 기준 7.0 → P1
  action_type: PATCH_AVAILABLE
  cwe_list: CWE-295, CWE-416
  Structured context (respect allowed_claims/forbidden_claims strictly): {"validation_status": "VALID", "reachability": "POTENTIALLY_REACHABLE", "vulnerable_feature_confirmed": false, "attacker_input_path_confirmed": false, "action_type": "PATCH_AVAILABLE", "allowed_claims": ["package installation confirmed", "process load confirmed (loaded=true)", "association with an externally/locally exposed process confirmed"], "forbidden_claims": ["confirmed external exploitation", "confirmed vulnerable feature activation", "RCE without a confirmed input path", "attacker input path confirmed"]}
  cti_context (supplementary background only — see rule 8):
    - [source: fireeye-operation-saffron-rose.pdf, similarity=0.699] The Ajax Security Team has historically leveraged OpenSSL-linked network services as an initial foothold in targeted intrusions against defense-sector organizations.
  2 CVE(s) included:
    - CVE-2026-45447 (severity=HIGH, cvss=8.8, reachability=POTENTIALLY_REACHABLE, fixed_version=1:3.5.5-4.0.1.el9_8)
    - CVE-2026-34182 (severity=HIGH, cvss=9.1, reachability=POTENTIALLY_REACHABLE, fixed_version=1:3.5.5-4.0.1.el9_8)
  Sample collection-agent rationale: 외부노출(mysqld:3306 가 openssl-libs 사용) → HIGH · 벤더 조치버전 존재

There are 1 groups in total. Output a JSON with exactly 1 items in the "items" array (each item's index must match its [N] above).
```

`cti_context` 줄은 `_group_cti_block()`이 만든다 — Qdrant 검색 결과가 없으면
`cti_context: none retrieved` 한 줄만 들어간다. `Structured context` JSON은
`_group_claims_block()`이 만든다.

---

## 3. 총평/권고/결론 합성

- 파일: `app/agent/prompts.py`
- 함수: `REPORT_SYNTHESIS_SYSTEM_PROMPT` (시스템) + `build_report_synthesis_user_prompt()` (사용자)
- 호출부: `app/agent/nodes.py`의 `synthesize_narrative()` — 그룹 분석이 전부 끝난 뒤 1회 호출
- 출력 스키마: `app/schemas/report.py`의 `ReportNarrative`(`executive_summary`/`overall_recommendation`/`conclusion`)

### 3.1 시스템 프롬프트 (원문 그대로)

```text
You are a cybersecurity analyst writing the narrative sections of a vulnerability assessment report for an internal enterprise system. Using the host overview, the deterministically computed risk score components/level/confidence metrics, the statistics, and the already-analyzed remediation groups given below, write in English: an executive summary (executive_summary), overall remediation recommendations (overall_recommendation), and a conclusion (conclusion).

The risk score components (threat_score/environment_score/impact_score/overall_score) and risk_level are already computed by fixed rules — quote them as given, do not re-judge them yourself. If "provisional" is true, you MUST mention that the score is provisional because asset criticality is not yet confirmed. The host's information-sensitivity grade (things like an "S" grade) is a completely separate, unrelated metric from the risk level — never conflate them (only mention it if truly necessary, and never as if it were a risk level). Do not write definitive claims we cannot verify from this data (e.g. "this is confirmed to be exploited externally") — keep the hedged language "potentially reachable". Never claim P0/"immediate 24-hour action" urgency if the P0 count is zero. For groups whose action_type is NO_FIX_MITIGATION_REQUIRED, do not recommend "apply the patch" — recommend mitigations instead, with high urgency if externally reachable, not "handle later".

**Precision rules (must follow — these were flagged as errors in a previous version of this report):**
- NEVER say a number of "vulnerabilities" equal to total_findings. total_findings counts finding INSTANCES (the same CVE can repeat across many packages/containers) — always call it "finding instances", and separately cite unique_cve_count as "unique CVEs" when you mean actual distinct vulnerabilities.
- NEVER imply that all total_findings finding instances are inside the remediation groups. Only "analyzed_findings" instances were selected and organized into "total_group_count" groups; the rest were classified by tier only (not individually narrated). Say something like "X finding instances were selected for deep analysis and organized into Y groups" — do not say "Y groups covering X findings" if X is total_findings.
- Restart guidance: "restart_required_group_count" groups have CONFIRMED restart necessity (stale library already detected), and separately "restart_check_group_count" groups need a post-remediation rescan to check if restart is needed. If restart_check_group_count > 0, do NOT say "no restart is needed" or "no reboot work is required" as a blanket statement — patching a loaded shared library commonly requires a service/container restart, so say that a rescan after remediation is needed to confirm, even though no already-stale process was found in this scan.

executive_summary: 3-5 sentences summarizing risk_level/overall_score (mentioning provisional status if applicable) and the most urgent remediation groups. Do not restate raw finding/group counts in detail (they're already shown deterministically elsewhere in the report) — focus on the qualitative risk narrative.
overall_recommendation: an overall prioritization/scheduling strategy, not a list of individual groups. Explicitly separate patchable items from vendor-unfixed items needing mitigation.
conclusion: a short closing statement for the report.

**Output ONLY JSON matching this schema.** No explanation, no markdown, no code fences.

{
  "executive_summary": "string (English)",
  "overall_recommendation": "string (English)",
  "conclusion": "string (English)"
}
```

### 3.2 사용자 프롬프트 — 렌더링 예시

`build_report_synthesis_user_prompt()`를 실제 데이터 형태로 호출한 결과(그룹 목록은 1개만
축약):

```text
Host info:
- Hostname: deskmini-x300
- OS: ubuntu 24.04
- Kernel: 6.8.0-138-generic (running: 6.8.0-138-generic, latest: 6.8.0-139-generic, reboot needed: 1)
- (reference only, unrelated to risk level) System-suggested information grade: S (not confirmed by a human) — S 초안. 외부노출 63개.

Deterministically computed risk score (use these values as-is, do not re-derive):
- threat_score=11.0 / environment_score=55.0 / impact_score=60 (provisional=True) / overall_score=38.7/100
- risk_level=MEDIUM (thresholds: {"CRITICAL": 75, "HIGH": 45, "MEDIUM": 20, "LOW": 0})
- scoring_version=risk-scoring-v2.0
- Confidence: collection_completeness=100% / matching_confidence=99% / reachability_confidence=100% / analysis_confidence=82%
- Priority tier distribution (P0=immediate, REVIEW=data conflicts excluded from normal groups): {"P0": 0, "P1": 47, "P2": 69, "P3": 3210, "REVIEW": 37}

Vulnerability statistics:
- 3363 total findings (806 unique CVEs, 321 unique packages)
- Organized into 40 remediation groups (22 analyzed with AI narrative, 0 held for review by LLM validation, 18 excluded for data-validation conflicts)
- Vendor unfixed (no_fix): 2183 findings
- Restart status: 0 groups with CONFIRMED restart necessity (stale library already detected) / 22 groups need a post-remediation rescan to check restart necessity (do not claim "no restart needed" if this is > 0)

Change vs previous scan: No previous scan available (first analysis).

Data collection coverage warnings: none

Top-priority remediation groups (up to 15, already analyzed — do not re-analyze, just summarize):
- [P1] openssl @ vulnagent-db (2 CVEs, action_type=PATCH_AVAILABLE): (여기엔 실제로는 2번 분석 단계에서 생성된 risk_summary가 들어간다)
```

---

## 4. 영→한 번역

- 파일: `app/agent/translate.py`
- 함수: `TRANSLATE_INSTRUCTION` + `_build_translation_prompt()`
- 호출부: `app/agent/nodes.py`의 `analyze_risks()`(그룹 배치당 1회) / `synthesize_narrative()`(1회) — `translate_fields()`를 통해 호출
- 특이사항: **시스템 메시지를 쓰지 않는다.** translategemma에게 system + 규칙 목록 프롬프트를
  주면 번역 대신 텍스트에 대한 설명/답변을 하려 드는 것을 실측으로 확인했다. 그래서 지시문과
  원문을 하나의 user 메시지로 합쳐서 보낸다.

### 4.1 지시문 (원문 그대로)

```text
Translate the following tagged English text blocks into natural, professional Korean for a security report. Keep each [tag] marker exactly as-is at the start of its translated block, in the same order. Do not translate CVE IDs, package names, version strings, port numbers, or source file names (e.g. report.pdf). Output only the tagged translations, nothing else.
```

### 4.2 사용자 메시지 — 렌더링 예시

`_build_translation_prompt()`를 실제로 호출한 결과(지시문 + `[tag] 텍스트` 목록을 한
user 메시지로 합침):

```text
Translate the following tagged English text blocks into natural, professional Korean for a security report. Keep each [tag] marker exactly as-is at the start of its translated block, in the same order. Do not translate CVE IDs, package names, version strings, port numbers, or source file names (e.g. report.pdf). Output only the tagged translations, nothing else.

[1-summary] The curl package in the vulnagent-web container is potentially reachable through an externally exposed Apache2 service on port 80.
[1-impact] An attacker could potentially exploit the curl vulnerability via the Apache2 web interface.
```

응답이 일부 `[tag]`를 누락하면(끝까지 실패 시 최대 1회 재시도), 다음 한국어 안내 메시지를
대화에 추가해 한 번 더 요청한다:

```text
일부 [tag] 항목이 누락되었습니다. 입력으로 주어진 모든 태그를 정확히 동일한 형식으로 다시 출력하세요.
```
