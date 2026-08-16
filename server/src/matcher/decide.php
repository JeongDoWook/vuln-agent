<?php
declare(strict_types=1);

/**
 * matcher/decide.php — **억제 게이트**. 후보 CVE 1건의 최종 판정이 전부 여기 있다.
 *   순서가 그 자체로 우선순위다: 상태분류 → 커널(실행 아님·CNA) → 억제 보류(런타임/서드파티)
 *   → ①버전 ②배포판 트래커 ③벤더 OVAL ④errata ⑤changelog → 조치불가(no_fix).
 *   **이 순서와 조건을 재배열하면 오탐/미탐이 곧바로 바뀐다**(#371: changelog 억제를 서드파티
 *   가드에서 분리한 것이 그 예다). 쪼개면 "어느 근거가 어느 가드에 걸리는지"가 파일 경계로
 *   흩어지므로 177줄이어도 한 함수·한 파일로 둔다.
 *
 * matcher.php 가 require 한다. 단위 테스트는 tests/matcher_suppress_test.php.
 */

if (!function_exists('vg_match_decide_cve')) {
    /**
     * 한 패키지의 CVE 후보 1건을 판정한다: 7단계 상태분류 → 억제 취소 신호(재시작/재부팅 필요는
     *   그대로 억제 불가로 반영) → 오탐 억제 4겹(①버전 ②배포판 트래커 ③벤더권고(OVAL) ④errata·
     *   changelog) → 조치불가(no_fix) 표시. **순서가 그 자체로 우선순위다** — 먼저 걸리는 조건이
     *   이기고, 뒤 조건은 평가되지 않는다(vg_match_scan 의 억제 겹 순서를 그대로 옮겼다).
     *   억제로 판정되면 suppress=true + reason 을, findings 로 남으면 false + 등급/근거를 반환한다.
     *   실제 INSERT 와 $counts 집계는 호출부(vg_match_scan)가 한다 — 두 종류의 prepared
     *   statement(tb_finding/tb_suppressed_finding)와 카운터는 스캔 1건에 하나뿐이라 여기서
     *   더 나누면 오히려 인자가 늘어난다.
     *
     * @param array $ctx 이 패키지의 vg_match_pkg_context() 반환값(패키지 단위로 한 번만 계산).
     * @param array $sup 이 스캔의 vg_load_suppression_evidence() 반환값(억제 근거 전체 묶음).
     */
    function vg_match_decide_cve(
        string $cveId, array $cand, array $p, string $mgr, ?array $ctr, int $ctrId, array $scan,
        array $ctx, array $kev, array $kernelFixed, array $sup
    ): array {
        $cvss  = $cand['cvss'];
        $inKev = isset($kev[$cveId]);
        [$status, $sev, $why] = vg_classify($ctx['le'], $ctx['running'], $ctx['pkgLoaded'], $inKev, $p['name']);

        // 실행 중이 아닌 커널: 그 코드는 지금 돌지 않는다 → 억제(근거는 남긴다).
        //   조치는 "패치"가 아니라 "그 커널로 부팅하지 않기"이고, 실제로 부팅하면
        //   그때 실행 커널이 바뀌어 다음 수집에서 정상적으로 취약점으로 잡힌다.
        if ($ctx['kernelNotRunning']) {
            return [
                'suppress' => true, 'sev' => $sev, 'cvss' => $cvss, 'inKev' => $inKev,
                'reason' => sprintf('실행 중이 아닌 커널(설치만 됨) — 지금 도는 커널은 %s 다. 부팅해야 활성화된다',
                                     (string) ($scan['running_kernel'] ?? '?')),
            ];
        }

        // 커널 CNA 억제: 업스트림(kernel.org)이 "구동 커널 버전엔 이 수정본이 들어 있다"고
        //   말해 준 경우. 배포판 조치안이 아니라 uname 의 **업스트림 버전**(6.18.34)으로 보므로,
        //   배포판 관할 밖의 커널(라즈베리 `1:6.18.34-1+rpt1`)도 정확히 판정된다.
        //
        //   **배포판 커널엔 쓰지 않는다**(!$isDistroPkg 조건). RHEL 커널은 5.14.0 위에 백포트를
        //   쌓은 것이라 업스트림 버전이 코드 내용을 대변하지 않는다 — "이 취약 코드는 6.1부터"를
        //   그대로 믿으면 Red Hat 이 6.1 의 기능을 5.14 로 백포트한 경우를 놓친다(미탐).
        //   배포판 커널은 트래커·OVAL 이 이미 정확히 판정한다. 여기는 **그들이 관할하지 않는
        //   커널만** 맡는다.
        if ($ctx['isKernelPkg'] && !$ctx['isDistroPkg'] && isset($kernelFixed[$cveId])) {
            return [
                'suppress' => true, 'sev' => $sev, 'cvss' => $cvss, 'inKev' => $inKev,
                'reason' => $kernelFixed[$cveId],
            ];
        }

        // 억제 보류에는 성격이 다른 두 종류가 있다. 섞어서 하나의 플래그로 두면
        //   "근거가 못 믿을 만해서" 와 "근거는 맞지만 지금 도는 코드가 옛 것이라서" 를
        //   구분할 수 없다 — changelog 억제는 앞엣것엔 안 걸리고 뒤엣것엔 걸려야 한다.

        // (1) 런타임 보류 — **근거의 종류를 가리지 않는다.** 벤더가 뭐라 하든 이 프로세스는
        //   여전히 옛 코드를 실행 중이라, 어떤 백포트 근거로도 억제하면 안 된다.
        $runtimeStale = ($ctx['staleEv'] !== null) || $ctx['kernelPending'];
        if ($ctx['staleEv'] !== null) {
            $why .= ' · 재시작 필요(패치됐지만 옛 라이브러리 사용 중: ' . $ctx['staleEv'] . ')';
        }
        // 커널이 패치됐지만 재부팅 전이면, 설치 버전으로 억제하면 안 된다(옛 커널이 실행 중).
        if ($ctx['kernelPending']) {
            $why .= sprintf(' · 재부팅 필요(설치 %s / 실행 중 %s — 패치된 커널이 아직 안 올라옴)',
                            (string) ($scan['kernel_latest'] ?? '?'),
                            (string) ($scan['running_kernel'] ?? '?'));
        }

        // (2) 서드파티 보류 — **버전 비교 계열 근거에만** 해당한다. 배포판 조치안과 버전
        //   체계가 달라 "설치 ≥ 조치" 를 못 믿고, 트래커·OVAL 은 애초에 이 저장소를 관할하지
        //   않는다. 억제하지 않고 근거에 출처를 남겨, 사람이 판단할 수 있게 한다.
        //   changelog 는 여기 걸리지 않는다 — 그 억제 자리의 주석 참고.
        if (!$ctx['isDistroPkg']) {
            $why .= sprintf(' · 서드파티 저장소(%s) 패키지 — 배포판 조치안과 버전 체계가 달라 자동 판정 불가',
                            (string) ($p['origin'] ?? '출처 미상'));
        }

        $canSuppress = !$runtimeStale && $ctx['isDistroPkg'];

        // 버전 억제: 설치 버전이 조치 버전 이상이면 이미 패치된 것.
        //   배포판 규칙(epoch·릴리스·틸드)대로 비교한다 — vg_ver_cmp.
        //   fixed 가 비어 있으면(피드가 조치안을 안 준 경우) 판단하지 않고 남긴다.
        $fixed = $cand['fixed'];
        if ($canSuppress && $fixed !== null && $fixed !== '' && $cand['cmpver'] !== ''
            && vg_ver_cmp($cand['cmpver'], (string) $fixed, $mgr) >= 0) {
            return [
                'suppress' => true, 'sev' => $sev, 'cvss' => $cvss, 'inKev' => $inKev,
                'reason' => sprintf('설치 %s ≥ 조치 %s → 이미 패치됨', $cand['cmpver'], $fixed),
            ];
        }

        // 배포판 벤더 억제(데비안 보안 트래커 · 우분투 보안 OVAL): 벤더가 이 패키지의 이 CVE 를
        //   "아직 취약"으로 보지 않았다면 백포트로 이미 고쳐진 것이다(벤더의 패치 상태가 근거다).
        //   **컨테이너에도 적용된다** — 맵이 대상별로 갈려 있어(자기 릴리스 · 자기 패키지)
        //   호스트 상태가 컨테이너로 새지 않는다. hostEvidenceOk 가 아니라 isDistroPkg 로
        //   거른다: 서드파티 저장소 패키지는 트래커 관할이 아니므로 여전히 억제하지 않는다.
        if ($canSuppress && $ctx['isDistroPkg'] && vg_is_os_manager($mgr)
            && ($sup['useDebsecan'][$ctrId] ?? false)
            && !isset($sup['debsecan'][$ctrId][$p['name']][$cveId])) {
            return [
                'suppress' => true, 'sev' => $sev, 'cvss' => $cvss, 'inKev' => $inKev,
                'reason' => ($sup['trackerLabel'][$ctrId] ?? '배포판 보안 트래커') . '가 ' . $p['name'] . ' 의 ' . $cveId
                    . ' 를 해당 없음으로 판정 → 백포트로 이미 수정됨'
                    . ($ctr !== null ? ' (컨테이너 ' . (string) $ctr['cid'] . ')' : ''),
            ];
        }

        // 중앙 벤더권고(OVAL) 억제: RHEL 계열의 백포트 판정. 데비안 트래커의 rpm 판이다.
        //   대상별로 갈린 맵이라(자기 벤더·자기 메이저) 컨테이너에도 안전하게 적용된다.
        //   설치 EVR ≥ 조치 EVR 이면 이미 패치된 것 — 백포트라 업스트림 버전만 보면 낮아 보인다.
        $veEv = $sup['vendorErrata'][$ctrId][$p['name']][$cveId] ?? null;
        if ($canSuppress && $ctx['isDistroPkg'] && $veEv !== null) {
            return [
                'suppress' => true, 'sev' => $sev, 'cvss' => $cvss, 'inKev' => $inKev,
                'reason' => $p['name'] . ' — ' . $veEv,
            ];
        }

        // errata 억제: 벤더 보안권고가 이 설치 빌드에서 해당 CVE 를 고쳤다고 확인해 준 경우.
        //   버전이 낮아 보여도(백포트) 이미 패치된 것 → 실제 위험에서 제외.
        $erEv = $sup['errata'][$p['name']][$cveId]
            ?? ($p['source_pkg'] ? ($sup['errata'][$p['source_pkg']][$cveId] ?? null) : null);
        if ($canSuppress && $ctx['hostEvidenceOk'] && $erEv !== null) {
            $reason = $p['name'] . ' 에 적용된 벤더 보안권고가 ' . $cveId . ' 를 고침(백포트) → 이미 패치됨';
            if (is_string($erEv) && $erEv !== '') { $reason .= ' · ' . $erEv; }
            return ['suppress' => true, 'sev' => $sev, 'cvss' => $cvss, 'inKev' => $inKev, 'reason' => $reason];
        }

        // 백포트 억제: 이 빌드의 changelog 에 해당 CVE 수정 기록이 있으면
        //   버전이 낮아 보여도 이미 패치된 것 → 실제 위험에서 제외(오탐 제거).
        //
        //   **서드파티 저장소 패키지에도 적용한다** — `$canSuppress`(서드파티 가드 포함) 대신
        //   `$runtimeStale` 만 본다. 서드파티 가드의 사유는 "배포판 조치안과 **버전 체계**가
        //   달라 비교를 못 믿는다" 인데, changelog 는 버전을 비교하지 않는다. 그 빌드 자신의
        //   변경 기록에 CVE 번호가 박혀 있느냐만 보므로 EVR 체계와 무관하고, 오히려 배포판
        //   트래커·OVAL 이 관할하지 않는 서드파티 빌드에서는 **유일한 백포트 근거**다.
        //   실측 근거는 docs/dev/archive/changelog-억제층-실측.md — 서드파티 가드에 막혀 남아 있던
        //   호스트 4,088건을 벤더 1차 소스와 전수 대조했더니 **정탐이 0건**이었다(라즈베리파이
        //   6대는 HIGH 70건 중 20건이 이미 패치된 오탐). 걷히는 건 중 no_fix·KEV 는 0건이라
        //   "조치 불가"나 "실제 악용 중"인 것을 지우지 않는다.
        //
        //   반면 **컨테이너는 그대로 제외한다**($ctr === null). changelog 는 호스트에서 긁은
        //   것이라 컨테이너 패키지에 적용하면 미탐이다 — 같은 실측에서 컨테이너 5,404건은
        //   벤더 기준으로 **전부 아직 취약**했다(호스트의 openssl 이 패치됐다는 기록은 그 안에서
        //   도는 debian:12 컨테이너의 openssl 과 무관하다).
        //   재시작·재부팅 대기($runtimeStale)에는 여전히 걸린다 — 근거가 맞아도 지금 도는
        //   코드가 옛 것이면 억제하면 안 되기 때문이다.
        $bpEv = $sup['backport'][$p['name']][$cveId]
            ?? ($p['source_pkg'] ? ($sup['backport'][$p['source_pkg']][$cveId] ?? null) : null);
        if (!$runtimeStale && $ctr === null && $bpEv !== null) {
            $reason = $p['name'] . ' changelog 에 ' . $cveId . ' 수정 기록(백포트) → 버전이 낮아 보여도 패치됨';
            if (!$ctx['isDistroPkg']) {
                $reason .= ' · 서드파티 저장소(' . (string) ($p['origin'] ?? '출처 미상') . ') 빌드 자신의 기록';
            }
            if (is_string($bpEv) && $bpEv !== '') { $reason .= ' · ' . $bpEv; }
            return ['suppress' => true, 'sev' => $sev, 'cvss' => $cvss, 'inKev' => $inKev, 'reason' => $reason];
        }

        // 조치 불가(벤더가 아직 안 고침) — 등급은 그대로 두되 별도 축으로 표시한다.
        //   덜 위험해서가 아니라 **지금 할 수 있는 일이 없다**는 뜻이다(완화·격리가 답).
        $noFix = (string) ($cand['no_fix'] ?? '');

        // 데비안도 같은 축을 갖고 있었는데 우리가 버리고 있었다. 트래커는 CVE 마다
        //   **이 릴리스에 수정본이 나왔는지**(debsecan flags[3]=='F')를 알려준다.
        //   실측(raspberrypi5-00): 트래커가 답한 호스트 1,025건 중 708건이 수정본 없음이었다
        //   — HIGH 87건 중 지금 apt 로 고칠 수 있는 건 8건뿐인데, 화면엔 다 섞여 있었다.
        //   값이 0(수정본 없음)일 때만 붙인다. 에이전트 debsecan 경로는 값이 true 라 해당 없음.
        if ($noFix === '' && ($sup['debsecan'][$ctrId][$p['name']][$cveId] ?? null) === 0) {
            $noFix = ($sup['trackerLabel'][$ctrId] ?? '배포판') . ': 수정본 미배포';
        }

        if ($noFix !== '') {
            $why .= ' · 벤더 미수정(' . $noFix . ') — 조치 불가(수정본 없음)';
        }

        return [
            'suppress' => false, 'status' => $status, 'sev' => $sev, 'cvss' => $cvss,
            'inKev' => $inKev, 'noFix' => $noFix, 'why' => $why,
        ];
    }
}
