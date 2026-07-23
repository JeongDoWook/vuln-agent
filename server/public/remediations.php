<?php
declare(strict_types=1);
require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/view.php';
require __DIR__ . '/../src/remediation.php';
vg_require_menu('findings');
$pdo=vg_pdo(); $user=vg_current_user(); $notice=''; $error='';
if($_SERVER['REQUEST_METHOD']==='POST'){
    if(!vg_csrf_check($_POST['csrf']??null)){$error='요청 검증에 실패했습니다.';}
    elseif(!vg_has_role('admin','operator')){$error='조치 상태를 변경할 권한이 없습니다.';}
    else{
        $id=(int)($_POST['id']??0);$status=(string)($_POST['status']??'');$note=trim((string)($_POST['note']??''));$exceptionUntil=trim((string)($_POST['exception_until']??''));if($exceptionUntil!==''&&!preg_match('/^\\d{4}-\\d{2}-\\d{2}$/',$exceptionUntil)){$exceptionUntil='';}
        if($id<1||!in_array($status,VG_REMEDIATION_STATUSES,true)){$error='올바르지 않은 조치 요청입니다.';}
        else{
            $st=$pdo->prepare("UPDATE tb_remediation_cases SET status=?,assignee_user_id=CASE WHEN ?='IN_PROGRESS' THEN COALESCE(assignee_user_id,?) ELSE assignee_user_id END,resolution_note=CASE WHEN ?='RESOLVED' THEN ? ELSE resolution_note END,exception_reason=CASE WHEN ?='EXCEPTION' THEN ? ELSE NULL END,exception_until=CASE WHEN ?='EXCEPTION' AND ?<>'' THEN CONCAT(?,' 23:59:59') ELSE NULL END,completed_at=CASE WHEN ?='RESOLVED' THEN NOW() ELSE NULL END WHERE id=? AND is_deleted=0");
            $st->execute([$status,$status,$user['id'],$status,$note,$status,$note,$status,$exceptionUntil,$exceptionUntil,$status,$id]);
            vg_log_activity($pdo,'REMEDIATION',$id,'remediation_update',$status.' · '.$note,null,null,'USER');$notice='조치 상태를 저장했습니다.';
        }
    }
}
$status=(string)($_GET['status']??'');if(!in_array($status,VG_REMEDIATION_STATUSES,true))$status='';
$overdue=(string)($_GET['overdue']??'');$q=trim((string)($_GET['q']??''));$page=vg_page();$perPage=vg_perpage();
$where=['r.is_deleted=0'];$params=[];
if($status!==''){$where[]='r.status=?';$params[]=$status;}
if($overdue==='1'){$where[]="r.due_at<NOW() AND r.status NOT IN ('RESOLVED','EXCEPTION')";}
if($q!==''){$where[]='(h.fqdn LIKE ? OR r.cve_id LIKE ? OR r.package_name LIKE ?)';$params=array_merge($params,array_fill(0,3,'%'.$q.'%'));}
$whereSql=implode(' AND ',$where);
$countSt=$pdo->prepare("SELECT COUNT(*) FROM tb_remediation_cases r JOIN tb_hosts h ON h.id=r.host_id WHERE {$whereSql}");
$countSt->execute($params);$total=(int)$countSt->fetchColumn();
$offset=($page-1)*$perPage;
$sql="SELECT r.*,h.fqdn,u.username,DATEDIFF(r.due_at,NOW()) due_days FROM tb_remediation_cases r JOIN tb_hosts h ON h.id=r.host_id LEFT JOIN tb_users u ON u.id=r.assignee_user_id WHERE {$whereSql} ORDER BY FIELD(r.status,'OPEN','IN_PROGRESS','EXCEPTION','RESOLVED'),r.due_at ASC LIMIT {$perPage} OFFSET {$offset}";
$st=$pdo->prepare($sql);$st->execute($params);$rows=$st->fetchAll();
$counts=$pdo->query("SELECT SUM(status='OPEN') open_count,SUM(status='IN_PROGRESS') progress_count,SUM(status='EXCEPTION') exception_count,SUM(status NOT IN ('RESOLVED','EXCEPTION') AND due_at<NOW()) overdue_count FROM tb_remediation_cases WHERE is_deleted=0")->fetch();
vg_header('조치 관리','remediations');
vg_page_title('조치 관리','REMEDIATION WORKSPACE','같은 자산·CVE·패키지를 하나의 조치 단위로 묶고 내부 SLA만 추적합니다.');
if($notice)vg_alert(['type'=>'ok','title'=>$notice]);if($error)vg_alert($error);
?>
<div class="cards cards--grid">
  <div class="kpi"><span>신규</span><strong><?= (int)$counts['open_count'] ?></strong></div>
  <div class="kpi"><span>진행 중</span><strong><?= (int)$counts['progress_count'] ?></strong></div>
  <div class="kpi"><span>예외</span><strong><?= (int)$counts['exception_count'] ?></strong></div>
  <div class="kpi tone-high"><span>내부 SLA 초과</span><strong><?= (int)$counts['overdue_count'] ?></strong></div>
</div>
<form class="toolbar" method="get"><input type="search" name="q" value="<?= vg_h($q) ?>" placeholder="호스트, CVE, 패키지 검색"><select name="status"><option value="">전체 상태</option><?php foreach(VG_REMEDIATION_STATUSES as $v):?><option value="<?= $v ?>"<?= $status===$v?' selected':'' ?>><?= vg_h($v) ?></option><?php endforeach?></select><label class="inline"><input type="checkbox" name="overdue" value="1"<?= $overdue==='1'?' checked':'' ?>> SLA 초과만</label><button class="btn" type="submit">검색</button></form>
<?php
$headers=[['label'=>'조치 단위'],['label'=>'대상'],['label'=>'상태'],['label'=>'내부 기한'],['label'=>'담당'],['label'=>'변경']];
vg_table($headers,$rows,[
 'empty'=>['title'=>'조건에 맞는 조치 건이 없습니다','body'=>'필터를 바꾸거나 다음 수집을 기다려 주세요.'],
 'row_class'=>static fn(array $r):string=>((int)$r['due_days']<0&&!in_array($r['status'],['RESOLVED','EXCEPTION'],true))?'sev-high':'',
 'cell'=>[
  0=>static fn(array $r):string=>'<strong>'.vg_h($r['cve_id']).'</strong><div class="muted">'.vg_h($r['package_name']).'</div>',
  1=>static fn(array $r):string=>vg_h($r['fqdn']).($r['container_ref']!==''?'<div class="muted">'.vg_h($r['container_ref']).'</div>':''),
  2=>static fn(array $r):string=>'<span class="badge">'.vg_h($r['status']).'</span>',
  3=>static function(array $r):string{$late=(int)$r['due_days']<0&&!in_array($r['status'],['RESOLVED','EXCEPTION'],true);return '<span'.($late?' class="badge tone-high"':'').'>'.vg_h($r['due_at']??'-').'</span>'.($late?'<div class="muted">'.abs((int)$r['due_days']).'일 초과</div>':'');},
  4=>static fn(array $r):string=>vg_h($r['username']??'미지정'),
  5=>static function(array $r):string{if(!vg_has_role('admin','operator'))return '';$options='';foreach(VG_REMEDIATION_STATUSES as $v){$options.='<option value="'.$v.'"'.($r['status']===$v?' selected':'').'>'.$v.'</option>';}$csrf=vg_h(vg_csrf_token());return '<form method="post" class="inline-form"><input type="hidden" name="csrf" value="'.$csrf.'"><input type="hidden" name="id" value="'.(int)$r['id'].'"><select name="status">'.$options.'</select><input name="note" maxlength="1000" placeholder="조치·예외 사유"><input type="date" name="exception_until" aria-label="예외 만료일"><button class="btn btn--sm">저장</button></form>';},
 ],
]);
if($rows){vg_page_nav($total,$perPage,$page);}
?><?php vg_footer();