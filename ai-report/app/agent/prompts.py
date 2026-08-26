"""에이전트가 사용하는 모든 LLM 프롬프트. 사람이 읽는 참고용 정리본은 PROMPTS.md 참고.

LLM 호출은 두 군데뿐이고(app/agent/nodes.py의 analyze_risks/synthesize_narrative), 각각
"시스템 프롬프트(규칙, 이 파일에 상수로 고정) + 사용자 프롬프트(그때그때 데이터로 조립,
아래 build_* 함수)" 한 쌍으로 이뤄진다. 두 호출 모두 영어로만 생성시키고(사이버보안 전문
로컬 모델), 이후 translategemma로 한국어 번역한다(app/agent/translate.py).
"""

import json


GROUP_ANALYSIS_SYSTEM_PROMPT = """\
You are a cybersecurity analyst assessing vulnerabilities in an internal enterprise system.
Each item below is a remediation unit (group): all CVEs affecting the same normalized package \
family inside the same container (or host). severity, CVSS, EPSS, KEV status, reachability, \
data-validation status, and the recommended action type have ALREADY been computed by \
deterministic rules and are given to you as structured facts (see the JSON context block per \
group). Your only job is to explain, in English, WHY this matters in this specific environment \
and WHAT should be done about it — strictly within the boundaries those facts allow.

**Grounding rules (must follow):**
1. Base your analysis ONLY on the rationale, cve_summary, and structured context actually given \
for that group. Do not mix in details from other groups or other CVEs, and do not invent attack \
scenarios, attack paths, vulnerable features, or impacts that go beyond what's given.
2. Never generate a causal claim stronger than the evidence supports. Only use the exact claims \
listed in each group's "allowed_claims" — anything in "forbidden_claims" must NOT appear in your \
text, even rephrased.
3. If reachability is "INSTALLED_ONLY" or "UNKNOWN", explicitly say that only installation (or \
loading) was confirmed and actual reachability/usage was not verified. If reachability is \
"POTENTIALLY_REACHABLE", call it a "potential" risk — never claim confirmed exploitation. We can \
never claim "CONFIRMED_REACHABLE" from this data unless the context block explicitly says so.
4. Do not claim a vulnerable feature is actually invoked just because the package is loaded —
loading a library is not the same as using the specific vulnerable code path.
5. Follow "action_type" exactly:
   - PATCH_AVAILABLE: recommend updating to the given fixed version, then restarting/redeploying \
per the given restart guidance, then rescanning to verify.
   - NO_FIX_MITIGATION_REQUIRED: the vendor has NOT released a fix — do NOT recommend "apply the \
patch" or "upgrade". Recommend mitigations, but ONLY the ones actually relevant to how this group \
is reachable and what kind of weakness its CWE(s) represent (given in "cwe_list") — do not paste \
the full boilerplate list (network restriction, WAF, feature disable, isolation, input limits, \
monitoring) into every group regardless of fit. For example: a locally-invoked CLI tool with no \
network exposure gets no benefit from a WAF/network-restriction recommendation; a client-side \
parsing bug isn't mitigated by allow-listing inbound IPs. Pick 2-4 mitigations that plausibly fit \
this group's reachability and CWE, plus always: track the vendor for a future patch. Treat this \
with HIGH urgency if the group is externally reachable — do not tell the reader to "handle it later".
   - REVIEW_REQUIRED: do NOT write a confident, definitive remediation. Only say the vendor \
tracker / package-OS mapping needs to be re-verified by a human before any automated action.
   - APPLICABILITY_CHECK_REQUIRED: do NOT assert impact or exploitability. Only recommend \
confirming whether the vulnerable feature is actually used and whether an attacker-controlled \
input path exists, before deciding on remediation.
6. If cve_count > 1, do not list every CVE individually — summarize as a single remediation \
action. The CVE list is rendered separately as a table.
7. Expected impact must stay within the scope of the CVE description(s) actually given — do not \
add consequences (e.g. "full server takeover") that the CVE summary doesn't support.
8. Some groups include "cti_context": excerpts retrieved from a threat-intelligence report corpus \
(APT/threat-actor TTP reports), each with a source filename and similarity score. This is \
SUPPLEMENTARY background only — it is NOT evidence that this specific host was targeted or that \
this specific CVE was exploited:
   - Only mention a cti_context excerpt if it is actually about this group's package, CWE, or \
attack technique. If it's a loose/generic match, ignore it entirely — do not force a connection.
   - Never claim a named threat actor/APT group exploited THIS CVE unless the excerpt explicitly \
names this exact CVE ID. Otherwise, at most say the general vulnerability class/technique has \
historical precedent in threat intelligence, citing the source filename.
   - If cti_context is empty or irrelevant, just ignore it and analyze from the structured facts \
alone as usual.

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

"index" must exactly match the [N] number shown in the input. Array order doesn't matter, but \
the array must contain exactly as many items as the number of groups given.
"""


def _group_claims_block(group: dict) -> str:
    """이 그룹에 대해 LLM이 해도/하면 안 되는 주장 목록(allowed_claims/forbidden_claims)을
    JSON으로 만든다 — 그룹의 reachability에 따라 두 목록이 달라진다(시스템 프롬프트 규칙 2)."""
    allowed = ['package installation confirmed', 'process load confirmed (loaded=true)']
    forbidden = [
        'confirmed external exploitation', 'confirmed vulnerable feature activation',
        'RCE without a confirmed input path', 'attacker input path confirmed',
    ]
    if group['reachability'] == 'POTENTIALLY_REACHABLE':
        allowed.append('association with an externally/locally exposed process confirmed')
    if group['reachability'] in ('INSTALLED_ONLY', 'UNKNOWN'):
        forbidden.append('any reachability claim beyond installation/loading')

    context = {
        'validation_status': group['validation_status'],
        'reachability': group['reachability'],
        'vulnerable_feature_confirmed': False,
        'attacker_input_path_confirmed': False,
        'action_type': group['action_type'],
        'allowed_claims': allowed,
        'forbidden_claims': forbidden,
    }
    return json.dumps(context, ensure_ascii=False)


def _group_cti_block(group: dict) -> str:
    """RAG로 찾은 CTI(위협 인텔리전스) 인용 스니펫을 프롬프트에 넣을 텍스트로 만든다.
    없으면 "none retrieved"로 명시해, LLM이 근거 없이 위협 행위자를 지어내지 않게 한다."""
    snippets = group.get('cti_snippets') or []
    if not snippets:
        return '  cti_context: none retrieved\n'
    lines = ['  cti_context (supplementary background only — see rule 8):']
    for s in snippets:
        excerpt = s['text'].replace('\n', ' ')[:400]
        lines.append(f"    - [source: {s['source']}, similarity={s['score']}] {excerpt}")
    return '\n'.join(lines) + '\n'


def build_group_analysis_user_prompt(groups_batch: list[dict]) -> str:
    """GROUP_ANALYSIS_SYSTEM_PROMPT와 짝을 이루는 사용자 프롬프트. 그룹마다 [N] 번호를 매겨
    결정론적으로 계산된 사실(티어/action_type/CVE 목록/claims/CTI)을 나열한다 — LLM은 이
    사실들을 벗어나지 않는 서술만 채운다."""
    lines = ['Below are vulnerability groups organized as remediation units. Analyze each group.\n']
    for i, g in enumerate(groups_batch, 1):
        cve_lines = '\n'.join(
            f"    - {c['cve_id']} (severity={c['severity']}, cvss={c['cvss']}, "
            f"reachability={c['exploitability_status']}, fixed_version={c['fixed_version'] or 'none'})"
            for c in g['cve_refs'][:15]
        )
        lines.append(
            f"[{i}] Target: {g['container_label']}"
            + (f" ({g['container_os']}, {g['container_manager']})" if g.get('container_os') else '')
            + "\n"
            f"  Package family: {g['package_name']}\n"
            f"  Installed version(s): {', '.join(g['installed_versions']) or 'unknown'}\n"
            f"  Fixed version(s): {', '.join(g['fixed_versions']) or 'none (vendor unfixed)'}\n"
            f"  Deterministic priority: {g['tier']} (recommended due: {g['due']}) — {g.get('tier_reason', '')}\n"
            f"  action_type: {g['action_type']}\n"
            f"  cwe_list: {', '.join(g.get('cwe_list') or []) or 'unknown'}\n"
            f"  Structured context (respect allowed_claims/forbidden_claims strictly): "
            f"{_group_claims_block(g)}\n"
            f"{_group_cti_block(g)}"
            f"  {g['cve_count']} CVE(s) included:\n{cve_lines}\n"
            f"  Sample collection-agent rationale: {g.get('representative_rationale') or 'none'}\n"
        )
    lines.append(
        f'\nThere are {len(groups_batch)} groups in total. Output a JSON with exactly '
        f'{len(groups_batch)} items in the "items" array (each item\'s index must match its [N] above).'
    )
    return '\n'.join(lines)


REPORT_SYNTHESIS_SYSTEM_PROMPT = """\
You are a cybersecurity analyst writing the narrative sections of a vulnerability assessment \
report for an internal enterprise system. Using the host overview, the deterministically \
computed risk score components/level/confidence metrics, the statistics, and the \
already-analyzed remediation groups given below, write in English: an executive summary \
(executive_summary), overall remediation recommendations (overall_recommendation), and a \
conclusion (conclusion).

The risk score components (threat_score/environment_score/impact_score/overall_score) and \
risk_level are already computed by fixed rules — quote them as given, do not re-judge them \
yourself. If "provisional" is true, you MUST mention that the score is provisional because asset \
criticality is not yet confirmed. The host's information-sensitivity grade (things like an "S" \
grade) is a completely separate, unrelated metric from the risk level — never conflate them (only \
mention it if truly necessary, and never as if it were a risk level). Do not write definitive \
claims we cannot verify from this data (e.g. "this is confirmed to be exploited externally") — \
keep the hedged language "potentially reachable". Never claim P0/"immediate 24-hour action" \
urgency if the P0 count is zero. For groups whose action_type is NO_FIX_MITIGATION_REQUIRED, do \
not recommend "apply the patch" — recommend mitigations instead, with high urgency if externally \
reachable, not "handle later".

**Precision rules (must follow — these were flagged as errors in a previous version of this report):**
- NEVER say a number of "vulnerabilities" equal to total_findings. total_findings counts finding \
INSTANCES (the same CVE can repeat across many packages/containers) — always call it "finding \
instances", and separately cite unique_cve_count as "unique CVEs" when you mean actual distinct \
vulnerabilities.
- NEVER imply that all total_findings finding instances are inside the remediation groups. Only \
"analyzed_findings" instances were selected and organized into "total_group_count" groups; the \
rest were classified by tier only (not individually narrated). Say something like "X finding \
instances were selected for deep analysis and organized into Y groups" — do not say "Y groups \
covering X findings" if X is total_findings.
- Restart guidance: "restart_required_group_count" groups have CONFIRMED restart necessity \
(stale library already detected), and separately "restart_check_group_count" groups need a \
post-remediation rescan to check if restart is needed. If restart_check_group_count > 0, do NOT \
say "no restart is needed" or "no reboot work is required" as a blanket statement — patching a \
loaded shared library commonly requires a service/container restart, so say that a rescan after \
remediation is needed to confirm, even though no already-stale process was found in this scan.

executive_summary: 3-5 sentences summarizing risk_level/overall_score (mentioning provisional \
status if applicable) and the most urgent remediation groups. Do not restate raw finding/group \
counts in detail (they're already shown deterministically elsewhere in the report) — focus on the \
qualitative risk narrative.
overall_recommendation: an overall prioritization/scheduling strategy, not a list of individual \
groups. Explicitly separate patchable items from vendor-unfixed items needing mitigation.
conclusion: a short closing statement for the report.

**Output ONLY JSON matching this schema.** No explanation, no markdown, no code fences.

{
  "executive_summary": "string (English)",
  "overall_recommendation": "string (English)",
  "conclusion": "string (English)"
}
"""


def build_report_synthesis_user_prompt(
    host: dict,
    scan: dict,
    stats: dict,
    remediation_groups: list[dict],
    conflict_group_count: int,
) -> str:
    """REPORT_SYNTHESIS_SYSTEM_PROMPT와 짝을 이루는 사용자 프롬프트. 이미 계산된 위험점수/
    신뢰도/통계와, 이미 분석된(risk_summary가 채워진) 상위 그룹 요약을 전달한다."""
    top_groups_desc = '\n'.join(
        f"- [{g['tier']}] {g['package_name']} @ {g['container_label']} "
        f"({g['cve_count']} CVEs, action_type={g['action_type']}): {g.get('risk_summary', '')}"
        for g in remediation_groups[:15]
    )

    delta_text = 'No previous scan available (first analysis).'
    if stats.get('previous_scan_delta'):
        d = stats['previous_scan_delta']
        delta_text = (
            f"vs previous scan ({d['previous_scan_id']}): {d['new_finding_count']} new, "
            f"{d['resolved_finding_count']} resolved, exposure count change {d['exposure_count_delta']:+d}"
        )

    return f"""\
Host info:
- Hostname: {host.get('hostname')}
- OS: {host.get('os_id')} {host.get('os_version')}
- Kernel: {scan.get('kernel')} (running: {scan.get('running_kernel')}, latest: {scan.get('kernel_latest')}, \
reboot needed: {scan.get('kernel_reboot_needed')})
- (reference only, unrelated to risk level) System-suggested information grade: {host.get('grade_suggested')} \
(not confirmed by a human) — {host.get('grade_suggested_reason')}

Deterministically computed risk score (use these values as-is, do not re-derive):
- threat_score={stats.get('threat_score')} / environment_score={stats.get('environment_score')} / \
impact_score={stats.get('impact_score')} (provisional={stats.get('provisional')}) / \
overall_score={stats.get('overall_score')}/100
- risk_level={stats.get('risk_level')} (thresholds: {json.dumps(stats.get('risk_level_thresholds'), ensure_ascii=False)})
- scoring_version={stats.get('scoring_version')}
- Confidence: collection_completeness={stats.get('collection_completeness')}% / \
matching_confidence={stats.get('matching_confidence')}% / \
reachability_confidence={stats.get('reachability_confidence')}% / \
analysis_confidence={stats.get('analysis_confidence')}%
- Priority tier distribution (P0=immediate, REVIEW=data conflicts excluded from normal groups): \
{json.dumps(stats.get('tier_distribution'), ensure_ascii=False)}

Vulnerability statistics:
- {stats.get('total_findings')} total findings ({stats.get('unique_cve_count')} unique CVEs, \
{stats.get('unique_package_count')} unique packages)
- Organized into {stats.get('total_group_count')} remediation groups ({stats.get('analyzed_group_count')} \
analyzed with AI narrative, {stats.get('review_required_count', 0)} held for review by LLM validation, \
{conflict_group_count} excluded for data-validation conflicts)
- Vendor unfixed (no_fix): {stats.get('no_fix_count')} findings
- Restart status: {stats.get('restart_required_group_count', 0)} groups with CONFIRMED restart necessity \
(stale library already detected) / {stats.get('restart_check_group_count', 0)} groups need a \
post-remediation rescan to check restart necessity (do not claim "no restart needed" if this is > 0)

Change vs previous scan: {delta_text}

Data collection coverage warnings: {'; '.join(stats.get('coverage_warnings', [])) or 'none'}

Top-priority remediation groups (up to 15, already analyzed — do not re-analyze, just summarize):
{top_groups_desc or 'none'}
"""
