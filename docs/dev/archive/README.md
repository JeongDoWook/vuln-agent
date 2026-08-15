# archive — 지난 작업의 실측 기록

여기 있는 문서는 **그때 그 자리에서 잰 값과 그 근거**다. 현행 규칙이 아니므로 코드를 고칠 때
기준으로 삼지 않는다 — 현행 규칙은 `docs/dev/` 루트(`architecture.md`·`화면-안내.md` 등)에 있다.
지우지 않는 이유는 "왜 그렇게 판단했나"의 근거가 여기에만 남아 있어서다.

| 문서 | 무엇을 잰 기록인가 | 측정 시점 |
|---|---|---|
| [changelog-억제층-실측.md](changelog-억제층-실측.md) | 운영 억제 144만 건 중 changelog 근거 억제가 0건이던 이유. 권고는 이미 적용됨(#371) | 2026-07-28 |
| [packages-screen-profiling.md](packages-screen-profiling.md) | 스모크 `[패키지 서브탭]` 14초의 실제 출처. 화면은 91ms | 2026-08-12 |
| [cleanup-evidence.md](cleanup-evidence.md) | 데드코드 제거(#599)의 제거 전 참조 증거 | 2026-08-15 |
