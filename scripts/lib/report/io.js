'use strict';

// gen-review.js / gen-report.js / gen-status.js가 공유하는 CLI 입출력 계약:
// <input.json> [output.html] 인자를 받아 파싱하고, 산출물은 입력과 같은
// 디렉토리에 <prefix>-<timestamp>.html 로 쓴다.
const fs = require('fs');
const path = require('path');

function loadInput(usage) {
  const args = process.argv.slice(2);
  if (!args[0]) {
    console.error(usage);
    process.exit(1);
  }

  const inputPath = path.resolve(args[0]);
  if (!fs.existsSync(inputPath)) {
    console.error(`❌ 파일 없음: ${inputPath}`);
    process.exit(1);
  }

  let data;
  try {
    // BOM 제거 — Windows 도구(PowerShell Out-File, 메모장 등)가 쓴 UTF-8 JSON에는 BOM이 흔하고,
    // JSON.parse는 BOM을 문법 오류로 본다. 산출물 JSON을 사람이 손으로 고치는 일이 있으므로
    // 여기서 흡수한다(2026-08-07 실측: gen-status가 정상 JSON을 파싱 실패로 거부).
    data = JSON.parse(fs.readFileSync(inputPath, 'utf8').replace(/^﻿/, ''));
  } catch (e) {
    console.error(`❌ JSON 파싱 실패: ${e.message}`);
    process.exit(1);
  }

  return { inputPath, outputArg: args[1], data };
}

function resolveOutputPath(inputPath, outputArg, prefix) {
  if (outputArg) return path.resolve(outputArg);
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  return path.join(path.dirname(inputPath), `${prefix}-${ts}.html`);
}

function writeReport(outputPath, html) {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, html, 'utf8');
}

module.exports = { loadInput, resolveOutputPath, writeReport };
