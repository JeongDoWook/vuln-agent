'use strict';

const fs = require('fs');
const path = require('path');

// 공통 스타일 SSOT — scripts/assets/report.css (직접 수정 금지). 산출물을
// 자기완결적으로 유지하기 위해 빌드타임에 인라인 주입한다.
function loadBaseCss() {
  return fs.readFileSync(path.join(__dirname, '..', '..', 'assets', 'report.css'), 'utf8');
}

module.exports = { loadBaseCss };
