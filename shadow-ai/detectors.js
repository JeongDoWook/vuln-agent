// detectors.js — 민감정보 탐지 공통 로직 (content/options/popup 이 공유, DRY)
//
// 이 파일은 브라우저 전역 스코프에 아래 3개를 노출한다.
//   VG_CATEGORIES : 카테고리 id -> 한글 라벨 (options.js 가 체크박스 목록을,
//                    popup.js 가 위반 배지 라벨을 여기서 만든다)
//   vgMask(str)   : 매칭 문자열을 앞 2~4글자만 남기고 마스킹
//   vgScan(text, enabledCategories) : text 안의 민감정보를 찾아 배열로 반환
'use strict';

var VG_CATEGORIES = {
  rrn: '주민등록번호',
  card: '신용카드번호',
  phone: '휴대폰번호',
  email: '이메일',
  apikey: 'API키/시크릿'
};

// 신용카드번호 오탐을 줄이기 위한 Luhn 체크섬 검증
function vgLuhnCheck(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48; // '0'..'9'
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// 앞 2~4글자만 남기고 나머지는 *** 로 마스킹
function vgMask(str) {
  if (!str) return str;
  const visible = str.length > 8 ? 4 : 2;
  return str.slice(0, visible) + '***';
}

// text 에서 활성화된 카테고리만 스캔해 [{type, label, match(마스킹됨), index}] 반환
function vgScan(text, enabledCategories) {
  const enabled = enabledCategories || {
    rrn: true, card: true, phone: true, email: true, apikey: true
  };
  const results = [];
  if (!text) return results;

  if (enabled.rrn) {
    const re = /\b\d{6}[-\s]?[1-4]\d{6}\b/g;
    let m;
    while ((m = re.exec(text))) {
      results.push({ type: 'rrn', label: VG_CATEGORIES.rrn, match: vgMask(m[0]), index: m.index });
    }
  }

  if (enabled.card) {
    // 13~16자리 숫자열(공백/하이픈 허용) 후보를 뽑은 뒤 Luhn 통과한 것만 채택
    const re = /\d(?:[ -]?\d){12,15}/g;
    let m;
    while ((m = re.exec(text))) {
      const digits = m[0].replace(/[ -]/g, '');
      if (digits.length >= 13 && digits.length <= 16 && vgLuhnCheck(digits)) {
        results.push({ type: 'card', label: VG_CATEGORIES.card, match: vgMask(m[0]), index: m.index });
      }
    }
  }

  if (enabled.phone) {
    const re = /\b01[016-9][-\s]?\d{3,4}[-\s]?\d{4}\b/g;
    let m;
    while ((m = re.exec(text))) {
      results.push({ type: 'phone', label: VG_CATEGORIES.phone, match: vgMask(m[0]), index: m.index });
    }
  }

  if (enabled.email) {
    const re = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    let m;
    while ((m = re.exec(text))) {
      results.push({ type: 'email', label: VG_CATEGORIES.email, match: vgMask(m[0]), index: m.index });
    }
  }

  if (enabled.apikey) {
    const patterns = [
      /AKIA[0-9A-Z]{16}/g,                  // AWS 액세스키
      /sk-[A-Za-z0-9]{20,}/g,                // OpenAI 키
      /ghp_[A-Za-z0-9]{36}/g,                // GitHub PAT
      /xox[baprs]-[A-Za-z0-9-]+/g,           // Slack 토큰
      /-----BEGIN [A-Z ]*PRIVATE KEY-----/g  // 개인키 헤더
    ];
    for (const re of patterns) {
      let m;
      while ((m = re.exec(text))) {
        results.push({ type: 'apikey', label: VG_CATEGORIES.apikey, match: vgMask(m[0]), index: m.index });
      }
    }
  }

  return results;
}
