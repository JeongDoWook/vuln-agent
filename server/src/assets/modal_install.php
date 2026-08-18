<?php
declare(strict_types=1);

/**
 * assets/modal_install.php — 에이전트 설치 안내 모달(4단계 스테퍼)만 갖는다.
 *   설치를 처음 할 때 한 번 보는 안내라 목록 아래 늘 펼쳐두지 않고 버튼 뒤 모달로 둔다.
 */

/** @param string $ingest 에이전트가 POST 할 수집 엔드포인트(현재 접속 주소 기준). */
function vg_assets_render_install_modal(string $ingest): void
{
    /* 설치 안내는 자산을 처음 붙일 때 한 번 보는 것이다. 목록 아래 늘 펼쳐두면
     * 매일 보는 화면이 그만큼 길어진다 → 버튼 뒤 모달로. */
    vg_modal_open('agentInstall', '에이전트 설치 안내', 'modal--wide');
  ?>
    <div class="install-stepper" data-stepper>
      <div class="install-stepper__tabs" role="tablist" aria-label="에이전트 설치 단계">
        <?php foreach (['키 발급', '파일·CA', '설치 실행', '연결 확인'] as $i => $label): ?>
          <button type="button" role="tab" data-install-step="<?= $i ?>"
                  aria-controls="agentInstallStep<?= $i + 1 ?>"><?= $i + 1 ?>. <?= vg_h($label) ?></button>
        <?php endforeach; ?>
      </div>

      <section id="agentInstallStep1" role="tabpanel" data-install-step-panel="1">
        <h3>1. 호스트 전용 키 발급</h3>
        <p>대상 서버의 FQDN으로 <a href="/agent-tokens.php">에이전트 키</a>를 발급하고, 한 번만 보이는 원문을 복사합니다.</p>
        <p class="why"><strong>완료 조건:</strong> 토큰 원문을 안전한 임시 위치에 복사했습니다. 같은 FQDN의 기존 활성 키는 자동 폐기됩니다.</p>
        <div class="actions"><a class="btn btn--sm btn--ghost" href="/agent-tokens.php">키 발급 화면</a><button type="button" class="btn btn--sm btn--primary" data-step-next="1">다음: 파일 받기</button></div>
      </section>

      <section id="agentInstallStep2" role="tabpanel" data-install-step-panel="2">
        <h3>2. 설치 파일과 루트 CA 받기</h3>
        <p>레포 체크아웃 없이 기존 다운로드 경로에서 세 파일을 받아 대상 서버로 옮깁니다.</p>
        <div class="actions">
          <a class="btn btn--sm btn--ghost" href="/agent-dl.php?f=install-agent.sh" download>install-agent.sh</a>
          <a class="btn btn--sm btn--ghost" href="/agent-dl.php?f=vuln-inventory-agent.sh" download>vuln-inventory-agent.sh</a>
          <a class="btn btn--sm btn--ghost" href="/agent-dl.php?f=caddy-root.crt" download>caddy-root.crt</a>
        </div>
        <pre class="code">scp install-agent.sh vuln-inventory-agent.sh caddy-root.crt 대상서버:~/</pre>
        <p class="why"><strong>완료 조건:</strong> 대상 서버의 같은 디렉터리에 세 파일이 있습니다. CA가 503이면 중앙 관리자에게 추출을 요청한 뒤 다시 시도합니다.</p>
        <div class="actions"><button type="button" class="btn btn--sm btn--ghost" data-step-prev="0">이전</button><button type="button" class="btn btn--sm btn--primary" data-step-next="2">다음: 설치 실행</button></div>
      </section>

      <section id="agentInstallStep3" role="tabpanel" data-install-step-panel="3">
        <h3>3. 대상 서버에서 설치 실행</h3>
        <p>대상 서버에는 POSIX <code>awk</code>와 HTTPS 전송용 <code>curl</code> 또는 <code>wget</code> 중 하나가 필요합니다. <code>jq</code>는 선택 사항입니다.</p>
        <pre class="code">sudo mkdir -p /opt/vuln-agent &amp;&amp; sudo cp ~/install-agent.sh ~/vuln-inventory-agent.sh ~/caddy-root.crt /opt/vuln-agent/
cd /opt/vuln-agent
sudo bash install-agent.sh
  중앙 서버 주소: <?= vg_h($ingest) ?>
  전송 토큰: ********
  수집 주기 [hourly]:</pre>
        <div class="actions"><?php vg_copy_btn('sudo bash install-agent.sh', '실행 명령 복사'); ?></div>
        <p class="why"><strong>완료 조건:</strong> 설치기가 성공으로 끝났습니다. systemd는 10초마다 명령을 확인하며, systemd가 없으면 cron 정기수집만 지원합니다.</p>
        <p class="why">실패하면 파일·CA 위치와 중앙 주소를 확인하고 같은 명령으로 <strong>다시 시도</strong>합니다. 제거는 <code>sudo bash install-agent.sh --uninstall</code>입니다.</p>
        <div class="actions"><button type="button" class="btn btn--sm btn--ghost" data-step-prev="1">이전</button><button type="button" class="btn btn--sm btn--primary" data-step-next="3">다음: 연결 확인</button></div>
      </section>

      <section id="agentInstallStep4" role="tabpanel" data-install-step-panel="4">
        <h3>4. 연결과 첫 자산 스캔 확인</h3>
        <?php /* '완료 조건' 한 줄은 걷었다 — 바로 위 문장이 이미 같은 조건(자동 등록 · 최신 수집
                 시각이 보이면 완료)을 말한다. 다른 단계의 '완료 조건' 은 그 위 문장에 없는 사실
                 (기존 키 자동 폐기 · CA 503 · systemd 유무)을 덧붙이므로 그대로 둔다. */ ?>
        <p>이 모달을 닫고 자산 목록에서 FQDN을 검색합니다. <strong>최신 수집</strong> 시각과 첫 탐지 결과가 보이면 완료입니다.</p>
        <p class="why">미수신이면 키의 FQDN·만료/폐기 상태, 대상 서버의 아웃바운드 HTTPS와 서비스 로그를 확인한 뒤 자산 스캔을 다시 시도합니다.</p>
        <?php /* 이 모달은 자산 목록(assets.php) 위에서만 열린다 — '/assets.php' 로 거는 링크는
                 보고 있는 화면을 다시 부르는 두 번째 문이었다. 위 문장이 시키는 대로 닫기만 한다. */ ?>
        <div class="actions"><button type="button" class="btn btn--sm btn--ghost" data-step-prev="2">이전</button><button type="button" class="btn btn--sm btn--primary" data-modal-close>닫고 목록에서 확인</button></div>
      </section>
    </div>
    <?php vg_modal_foot(null); ?>
  <?php vg_modal_close();
}
