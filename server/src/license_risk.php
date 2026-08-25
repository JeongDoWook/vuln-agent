<?php
declare(strict_types=1);

/**
 * license_risk.php — SPDX 라이선스 식별자 → 위험도(permissive/copyleft/unknown) 판정.
 *   packages.php의 언어 패키지 탭(?tab=lang)·sbom.php(SBOM 시각화 보기)가 공유하는 단일 헬퍼(DRY).
 *   목록은 바뀔 일이 거의 없는 알려진 SPDX 어휘라 하드코딩한다 — 범용 설정으로 감쌀 만큼
 *   가변적이지 않다.
 */

// 대표적인 permissive 라이선스 — 재배포·수정에 카피레프트 의무가 없다.
const VG_LICENSE_PERMISSIVE = [
    'MIT', 'MIT-0', 'Apache-2.0', 'Apache-1.1', 'BSD-2-Clause', 'BSD-3-Clause', 'BSD-4-Clause',
    'ISC', '0BSD', 'Unlicense', 'Zlib', 'BSL-1.0', 'PSF-2.0', 'X11', 'WTFPL', 'CC0-1.0', 'Python-2.0',
    'Ruby',
];
// 'Ruby' 를 permissive 로 둔 근거: 이 파일이 쓰는 copyleft 기준은 "재배포 시 소스 공개·동일 라이선스
//   의무"인데 Ruby License 에는 그 의무가 없다 — 조항 4 가 "상용 포함 어떤 소프트웨어에든 넣어도
//   된다"고 명시하고, 수정판 배포도 소스 공개 대신 사내 사용·바이너리 개명 같은 선택지를 준다
//   (share-alike 강제 없음). FSF 도 GPL 호환 '비카피레프트'로 분류하고 OSI 승인 목록에도 있다.
//   위 Python-2.0·Zlib·PSF-2.0 처럼 "MIT/BSD 계열은 아니지만 share-alike 가 없는" 항목과 같은
//   성격이다. 실측 gem 12건이 'Ruby OR BSD-2-Clause' 로 오는 것도(BSD-2-Clause 를 고를 수 있다)
//   Ruby 쪽이 그보다 무겁지 않다는 방증이다.

// 대표적인 copyleft 라이선스 — 재배포 시 소스 공개·동일 라이선스 의무가 붙어 조직 정책 검토가 필요하다.
const VG_LICENSE_COPYLEFT = [
    'GPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later',
    'LGPL-2.0', 'LGPL-2.0-only', 'LGPL-2.0-or-later', 'LGPL-2.1', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
    'LGPL-3.0', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
    'AGPL-1.0', 'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later',
    'MPL-1.1', 'MPL-2.0', 'EPL-1.0', 'EPL-2.0', 'CDDL-1.0', 'CDDL-1.1', 'CPL-1.0',
];

// 자유서술 라이선스 표기 → SPDX 식별자 별칭. pip METADATA 의 License: 헤더, CycloneDX
//   license.name 은 SPDX ID 가 아니라 이런 자유 텍스트로 온다(실측 다수). 전체 SPDX 텍스트
//   사전은 불필요(YAGNI) — 실사용 빈도 상위 표기만 다룬다. 매칭은 소문자 비교.
const VG_LICENSE_ALIASES = [
    'mit license'                              => 'MIT',
    'the mit license'                          => 'MIT',
    'bsd license'                              => 'BSD-3-Clause',
    'bsd'                                      => 'BSD-3-Clause',
    'new bsd license'                          => 'BSD-3-Clause',
    'simplified bsd license'                   => 'BSD-2-Clause',
    'apache software license'                  => 'Apache-2.0',
    'apache license 2.0'                       => 'Apache-2.0',
    'apache license, version 2.0'              => 'Apache-2.0',
    'apache 2.0'                               => 'Apache-2.0',
    'gnu general public license v2'            => 'GPL-2.0-only',
    'gnu general public license v2 (gplv2)'    => 'GPL-2.0-only',
    'gnu general public license v3'            => 'GPL-3.0-only',
    'gnu general public license v3 (gplv3)'    => 'GPL-3.0-only',
    'gnu lesser general public license v2'     => 'LGPL-2.0-only',
    'gnu lesser general public license v2.1'   => 'LGPL-2.1-only',
    'gnu lesser general public license v3'     => 'LGPL-3.0-only',
    'mozilla public license 2.0'               => 'MPL-2.0',
    'mozilla public license 2.0 (mpl 2.0)'     => 'MPL-2.0',
    'the unlicense'                            => 'Unlicense',
    'python software foundation license'       => 'PSF-2.0',
    'isc license'                              => 'ISC',
    'isc license (iscl)'                       => 'ISC',
    // 소문자 'ruby'. 목록 대조는 in_array(..., true) 라 대소문자를 구분한다(strtolower 는 이 별칭표
    //   조회에만 쓴다). rubygems gemspec 이 소문자로 적은 실측이 있어 이 한 줄을 둔다 — 'ruby'·
    //   'RUBY'·'Ruby' 가 전부 SPDX 식별자 'Ruby' 로 모인다.
    'ruby'                                     => 'Ruby',
];

// 별칭 매핑 + "GPL-3.0+" 류 '+' 접미사(≥ 이 버전) 정규화. 매칭 안 되면 원문 그대로 돌려준다
//   (미지의 자유 텍스트는 classify 에서 그대로 unknown 처리되는 게 안전하다 — 과탐보다 미탐이 낫다).
function vg_license_normalize_token(string $t): string
{
    $t = trim($t);
    if ($t === '') { return $t; }
    $alias = VG_LICENSE_ALIASES[strtolower($t)] ?? null;
    if ($alias !== null) { return $alias; }
    if (str_ends_with($t, '+')) {
        $base = substr($t, 0, -1);
        if (in_array($base, VG_LICENSE_COPYLEFT, true) || in_array($base, VG_LICENSE_PERMISSIVE, true)) {
            return $base . '-or-later';
        }
    }
    return $t;
}

/**
 * SPDX 식별자(또는 "MIT OR Apache-2.0"·"(MIT OR Apache-2.0)" 같은 SPDX 표현식) →
 *   permissive|copyleft|unknown. 복합 표현식은 토큰(OR/AND/WITH/쉼표로 분리) 중 하나라도
 *   copyleft 면 보수적으로 copyleft 로 본다 — 라이선스 위험 판정은 놓치는 것(미탐)이
 *   잘못 띄우는 것(과탐)보다 훨씬 나쁘다. 자유서술 표기는 토큰화 전에 별칭 정규화를 거친다.
 */
function vg_license_classify(?string $license): string
{
    $s = trim((string) $license);
    if ($s === '') { return 'unknown'; }

    $norm = vg_license_normalize_token($s);
    if (in_array($norm, VG_LICENSE_COPYLEFT, true)) { return 'copyleft'; }
    if (in_array($norm, VG_LICENSE_PERMISSIVE, true)) { return 'permissive'; }

    // npm 표준 표기 "(MIT OR Apache-2.0)" 의 괄호를 벗기고 OR/AND/WITH·쉼표로 토큰화한다.
    $stripped = preg_replace('/[()]/', '', $s) ?? $s;
    $tokens = preg_split('/\s*(?:,|\bOR\b|\bAND\b|\bWITH\b)\s*/i', $stripped) ?: [$stripped];
    $hasCopyleft = false;
    $hasPermissive = false;
    foreach ($tokens as $t) {
        $t = vg_license_normalize_token(trim($t));
        if ($t === '') { continue; }
        if (in_array($t, VG_LICENSE_COPYLEFT, true)) { $hasCopyleft = true; }
        elseif (in_array($t, VG_LICENSE_PERMISSIVE, true)) { $hasPermissive = true; }
    }
    if ($hasCopyleft) { return 'copyleft'; }
    if ($hasPermissive) { return 'permissive'; }
    return 'unknown';
}

// 위험도 → 한글 라벨.
function vg_license_risk_label(string $risk): string
{
    return ['permissive' => '허용적', 'copyleft' => '카피레프트', 'unknown' => '미상'][$risk] ?? '미상';
}

// 위험도 → 뱃지 톤(vg_badge 와 함께 쓴다). 카피레프트=위험(high), 허용적=안전(low), 미상=muted.
function vg_license_risk_tone(string $risk): string
{
    return ['permissive' => 'low', 'copyleft' => 'high', 'unknown' => 'muted'][$risk] ?? 'muted';
}
