<?php
declare(strict_types=1);

/**
 * netiface.php — "이 인터페이스가 가상인가" 판단의 SSOT.
 *
 *   컨테이너·가상 브리지·오버레이가 만든 인터페이스는 어느 호스트에나 비슷하게 있고,
 *   밖에서 그 주소로 그 자산에 닿지도 않는다(실측 deskmini-x300: IP 6개 중 5개가
 *   docker0·브리지 3개·calico). 자산 목록의 대표 IP 선정과 라우팅 파싱이 **같은 판단**을
 *   해야 하므로 규칙을 한 곳에 둔다 — 두 벌이면 한쪽만 고쳐져 어긋난다.
 *
 *   이름으로 거른다(대역이 아니라): 172.17/16 은 도커 기본값이지만 사내에서 실제로 쓰는
 *   기관도 있어 대역으로 자르면 진짜 주소를 숨기게 된다.
 */

/** 가상 인터페이스로 보는 이름 접두사. */
const VG_VIRTUAL_IFACES = ['docker', 'br-', 'virbr', 'veth', 'cali', 'cni', 'flannel',
                           'vxlan', 'kube', 'tun', 'tap', 'lo'];

/**
 * 인터페이스명이 가상 부류인가. 빈 값·NULL 은 **가상이 아니다** 로 본다 —
 *   가상이라는 근거가 없는데 그렇게 취급하는 것은 추측이고, iface 가 비어 있는 옛 백필
 *   행이야말로 그 호스트의 유일한 주소인 경우가 많다.
 */
function vg_iface_is_virtual(?string $iface): bool
{
    $iface = strtolower(trim((string) $iface));
    if ($iface === '') { return false; }
    foreach (VG_VIRTUAL_IFACES as $prefix) {
        if (strncmp($iface, $prefix, strlen($prefix)) === 0) { return true; }
    }
    return false;
}
