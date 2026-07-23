#!/usr/bin/env bash
# fw_detect 파서 단위 검증 — agent/vuln-inventory-agent.sh 의 nft/iptables 노출 강등 로직.
#   서버 스택 없이 도는 순수 단위 검사(샘플 룰셋 문자열을 파서 함수에 먹여 assert).
#   원칙: **확신이 있을 때만 강등**. policy drop 을 확인 못 하거나 하위 체인 jump 로
#   accept 를 따라갈 수 없으면 "@@UNTRUSTED@@"(=강등 안 함, EXTERNAL 유지)여야 한다.
set -u
cd "$(dirname "$0")/.." || exit 2
AGENT="agent/vuln-inventory-agent.sh"

# 대상 함수 3개만 스크립트에서 뽑아 로드한다(전체 실행 없이).
extract() { awk -v fn="$1" '$0 ~ "^"fn"\\(\\) \\{"{p=1} p{print} p && NR>1 && /^}/{exit}' "$AGENT"; }
eval "$(extract fw_parse_nft)"
eval "$(extract fw_parse_ipt)"
eval "$(extract fw_port_allowed)"

FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n     기대=[%s] 실제=[%s]\n' "$1" "$2" "$3"; FAIL=1; }
# 정규화: 파서 출력을 fw_detect 와 동일하게 정렬/포맷
norm() { tr ' ' '\n' | grep -E '^[0-9]+(-[0-9]+)?/(tcp|udp)$' | sort -u | paste -sd' ' -; }
eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }

echo "== nftables =="

# 1) policy drop + 단순 dport set accept → 22/80/443 만 허용
RS='table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		iif "lo" accept
		ct state established,related accept
		tcp dport { 22, 80, 443 } accept
	}
	chain forward { type filter hook forward priority 0; policy drop; }
}'
OUT=$(printf '%s\n' "$RS" | fw_parse_nft); ALLOW=$(printf '%s' "$OUT" | norm)
eq "drop+dport{22,80,443}: 허용집합" "22/tcp 443/tcp 80/tcp" "$ALLOW"
FW_KIND="nftables"; FW_ALLOW="$ALLOW"
fw_port_allowed 22 tcp && ok "  → 22/tcp 허용(EXTERNAL 유지)" || bad "22/tcp" "허용" "차단"
fw_port_allowed 3306 tcp && bad "3306/tcp" "차단(FILTERED)" "허용" || ok "  → 3306/tcp 차단(FILTERED)"

# 2) policy accept → 강등 안 함(@@UNTRUSTED@@)
RS='table inet filter {
	chain input {
		type filter hook input priority 0; policy accept;
		tcp dport 22 accept
	}
}'
OUT=$(printf '%s\n' "$RS" | fw_parse_nft)
eq "policy accept: 강등 안 함" "@@UNTRUSTED@@" "$OUT"

# 3) input hook chain 없음(forward 만) → 강등 안 함
RS='table inet filter {
	chain forward { type filter hook forward priority 0; policy drop; }
}'
OUT=$(printf '%s\n' "$RS" | fw_parse_nft)
eq "input chain 없음: 강등 안 함" "@@UNTRUSTED@@" "$OUT"

# 4) policy drop 이지만 하위 체인 jump(calico 류) → 따라갈 수 없음 → 강등 안 함
RS='table ip filter {
	chain INPUT {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
		jump cali-INPUT
		tcp dport 22 accept
	}
	chain cali-INPUT { tcp dport 6443 accept }
}'
OUT=$(printf '%s\n' "$RS" | fw_parse_nft)
eq "drop+jump: 강등 안 함(숨은 accept 못 따라감)" "@@UNTRUSTED@@" "$OUT"

# 5) policy drop + 포트 범위
RS='table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		tcp dport 6000-6007 accept
		udp dport 53 accept
	}
}'
OUT=$(printf '%s\n' "$RS" | fw_parse_nft); ALLOW=$(printf '%s' "$OUT" | norm)
eq "drop+범위+udp: 허용집합" "53/udp 6000-6007/tcp" "$ALLOW"
FW_KIND="nftables"; FW_ALLOW="$ALLOW"
fw_port_allowed 6003 tcp && ok "  → 6003/tcp 범위 내 허용" || bad "6003/tcp" "허용" "차단"

# 6) policy drop, 서비스 포트 accept 전무(lo/established 만) → 신뢰하되 허용집합 비어 전부 FILTERED
RS='table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		iif "lo" accept
		ct state established,related accept
	}
}'
OUT=$(printf '%s\n' "$RS" | fw_parse_nft)
[ "$OUT" != "@@UNTRUSTED@@" ] && ok "drop+accept없음: 신뢰(비-UNTRUSTED)" || bad "drop+accept없음" "신뢰(빈 허용집합)" "$OUT"
FW_KIND="nftables"; FW_ALLOW=$(printf '%s' "$OUT" | norm)
fw_port_allowed 22 tcp && bad "빈 허용집합 22/tcp" "차단" "허용" || ok "  → 22/tcp 차단(FILTERED)"

# 6b) 신뢰 체인 안 dport 인데 정규식이 못 알아본 accept(ct state new 섞임) → 계정 불가 → 강등 안 함
RS='table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		tcp dport 22 ct state new accept
	}
}'
OUT=$(printf '%s\n' "$RS" | fw_parse_nft)
eq "drop+dport에 ct state new 섞임: 강등 안 함(미탐 방지)" "@@UNTRUSTED@@" "$OUT"

# 6c) comment 접미사 붙은 단순 dport accept → 포트 추출(신뢰 유지)
RS='table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		iif "lo" accept
		tcp dport 80 accept comment "http"
	}
}'
OUT=$(printf '%s\n' "$RS" | fw_parse_nft); ALLOW=$(printf '%s' "$OUT" | norm)
eq "drop+dport accept comment: 80 추출" "80/tcp" "$ALLOW"

# 6d) 신뢰 체인 안 미지 accept(meta l4proto tcp accept) → 계정 불가 → 강등 안 함
RS='table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
		meta l4proto tcp accept
		tcp dport 22 accept
	}
}'
OUT=$(printf '%s\n' "$RS" | fw_parse_nft)
eq "drop+미지 accept(meta l4proto): 강등 안 함" "@@UNTRUSTED@@" "$OUT"

echo "== iptables =="

# 7) -P INPUT DROP + --dport 22 ACCEPT → 22 만
IPT='-P INPUT DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT'
OUT=$(printf '%s\n' "$IPT" | fw_parse_ipt); ALLOW=$(printf '%s' "$OUT" | norm)
eq "DROP+--dport 22: 허용집합" "22/tcp" "$ALLOW"

# 8) multiport --dports 22,80,443
IPT='-P INPUT DROP
-A INPUT -p tcp -m multiport --dports 22,80,443 -j ACCEPT'
OUT=$(printf '%s\n' "$IPT" | fw_parse_ipt); ALLOW=$(printf '%s' "$OUT" | norm)
eq "DROP+multiport: 허용집합" "22/tcp 443/tcp 80/tcp" "$ALLOW"

# 9) 커스텀 체인 jump(calico) → 강등 안 함
IPT='-P INPUT DROP
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -j cali-INPUT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT'
OUT=$(printf '%s\n' "$IPT" | fw_parse_ipt)
eq "DROP+커스텀 jump: 강등 안 함" "@@UNTRUSTED@@" "$OUT"

# 10) 소스 한정(-s) accept 는 외부 전체 허용 아님 → 제외(허용집합에서 빠져 FILTERED)
IPT='-P INPUT DROP
-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -j ACCEPT'
OUT=$(printf '%s\n' "$IPT" | fw_parse_ipt); ALLOW=$(printf '%s' "$OUT" | norm)
eq "DROP+소스한정 accept: 제외" "" "$ALLOW"

# 11) LOG/RETURN 은 미지 jump 가 아니므로 신뢰 유지
IPT='-P INPUT DROP
-A INPUT -j LOG
-A INPUT -p udp -m udp --dport 53 -j ACCEPT
-A INPUT -j RETURN'
OUT=$(printf '%s\n' "$IPT" | fw_parse_ipt); ALLOW=$(printf '%s' "$OUT" | norm)
eq "DROP+LOG/RETURN+dport53: 신뢰" "53/udp" "$ALLOW"

# 11b) 포트 특정 없는 광범위 accept(-p tcp -j ACCEPT) → 강등 안 함(모든 tcp 미탐 방지)
IPT='-P INPUT DROP
-A INPUT -p tcp -j ACCEPT'
OUT=$(printf '%s\n' "$IPT" | fw_parse_ipt)
eq "DROP+전체 tcp accept: 강등 안 함" "@@UNTRUSTED@@" "$OUT"

# 11c) 조건 없는 bare -j ACCEPT → 강등 안 함
IPT='-P INPUT DROP
-A INPUT -j ACCEPT'
OUT=$(printf '%s\n' "$IPT" | fw_parse_ipt)
eq "DROP+조건없는 accept: 강등 안 함" "@@UNTRUSTED@@" "$OUT"

echo "== 정책 게이트(호출부 시뮬레이션) =="
# 12) -P INPUT ACCEPT → 호출부가 파서를 부르지 않고 강등 안 함
IPT='-P INPUT ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT'
POL=$(printf '%s\n' "$IPT" | awk '/^-P INPUT /{print $3; exit}')
if [ "$POL" != "DROP" ] && [ "$POL" != "REJECT" ]; then ok "policy ACCEPT: 강등 안 함(게이트 차단)"; else bad "policy ACCEPT" "게이트 차단" "$POL"; fi

echo
if [ "$FAIL" = 0 ]; then echo "ALL PASS"; exit 0; else echo "SOME FAILED"; exit 1; fi
