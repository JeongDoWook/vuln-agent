'use strict';

/**
 * content-hash.js — 설치 매니페스트가 "같은 파일인가"를 판정하는 기준.
 *
 * **개행을 정규화한 뒤 해시한다.** 원시 바이트로 해시하면 Windows 호스트에서 세 번째
 * 기계적 게이트가 통째로 무력해진다:
 *
 *   호스트 저장소가 `.gitattributes` 에 `* text=auto` 를 두면(흔한 기본값) git 이 체크아웃
 *   때 LF → CRLF 로 바꾼다. 내용은 한 글자도 안 달라졌는데 바이트가 달라지므로
 *   `kit-manifest.js check` 가 **상시 exit 2** 를 낸다. 그러면 CI 에 걸 수 없고,
 *   사람은 곧 그 신호를 무시하게 된다 — 게이트가 있으나 마나가 된다.
 *
 *   더 나쁜 쪽은 install-kit 이다. 모든 파일이 "호스트가 고친 파일" 로 뜨므로
 *   `--force` 가 습관이 되고, 그 습관은 **진짜 호스트 수정을 말없이 덮어쓴다.**
 *   보호 장치가 스스로를 끄게 만드는 형태다.
 *
 * 실측(2026-08-08, vuln-agent): 매니페스트 대비 바이트 불일치 51건 / 개행 정규화 후
 * 실제 내용 차이 **0건**. 51건 전부가 CRLF ↔ LF 였다.
 *
 * 정규화 범위는 `\r\n → \n` 하나뿐이다. 그 외(공백 정리·BOM 제거·유니코드 정규화)는
 * 하지 않는다 — 그것들은 내용의 일부이고, 여기서 지우면 진짜 변경을 못 보게 된다.
 * 바이너리는 손대지 않는다(정규화하면 파일이 깨진다).
 */

const fs = require('fs');
const crypto = require('crypto');

const digest = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

// NUL 바이트가 있으면 바이너리로 본다 — git 이 쓰는 것과 같은 휴리스틱이다.
// 앞부분만 본다: 큰 파일 전체를 훑을 이유가 없고, 텍스트 파일이 8KB 뒤에서 갑자기
// NUL 로 시작하는 경우는 없다.
function isBinary(buf) {
  return buf.subarray(0, 8000).includes(0);
}

// 정규화된 내용 버퍼. 해시와 길이가 같은 기준을 보게 하려고 한 곳에서 만든다.
function contentBuffer(file) {
  const raw = fs.readFileSync(file);
  if (isBinary(raw)) return raw;
  return Buffer.from(raw.toString('utf8').replace(/\r\n/g, '\n'), 'utf8');
}

// 매니페스트에 적히는 해시.
function contentHash(file) {
  return digest(contentBuffer(file));
}

// 매니페스트에 적히는 크기. **디스크상 크기가 아니라 정규화된 내용의 크기다** —
// 해시와 같은 기준이어야 두 값이 서로 어긋나지 않는다(CRLF 트리에서 stat 크기를
// 적으면 "해시는 같은데 bytes 는 다른" 기록이 남는다).
function contentBytes(file) {
  return contentBuffer(file).length;
}

module.exports = { contentHash, contentBytes, isBinary };
