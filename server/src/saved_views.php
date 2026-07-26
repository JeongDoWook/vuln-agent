<?php
declare(strict_types=1);
const VG_SAVED_VIEW_PAGES=['findings'=>'/findings.php','remediations'=>'/remediations.php','assets'=>'/assets.php','cves'=>'/cves.php','packages'=>'/packages.php'];
function vg_saved_view_query(array $query):array{$out=[];foreach($query as $k=>$v){if(!preg_match('/^[a-z][a-z0-9_]{0,31}$/',(string)$k)||in_array($k,['csrf','page'],true)||is_array($v))continue;$out[$k]=mb_strimwidth((string)$v,0,500,'');}return $out;}
function vg_saved_view_bar(PDO $pdo,string $page):void{
 if(!isset(VG_SAVED_VIEW_PAGES[$page])||!function_exists('vg_current_user'))return;$u=vg_current_user();if(!$u)return;
 $st=$pdo->prepare('SELECT saved_view_id,name,query_json,is_default FROM tb_saved_view WHERE user_id=? AND page_code=? AND is_deleted=0 ORDER BY is_default DESC,name');$st->execute([$u['id'],$page]);$rows=$st->fetchAll();
 echo '<div class="saved-views"><span class="saved-views__label">저장된 보기</span>';
 foreach($rows as $r){$q=json_decode((string)$r['query_json'],true)?:[];$href=VG_SAVED_VIEW_PAGES[$page].'?'.http_build_query($q);echo '<a class="pill" href="'.vg_h($href).'">'.vg_h($r['name']).'</a>';}
 echo '<form method="post" action="/saved-view.php" class="saved-views__form"><input type="hidden" name="csrf" value="'.vg_h(vg_csrf_token()).'"><input type="hidden" name="page_code" value="'.vg_h($page).'"><input type="hidden" name="query_json" value="'.vg_h(json_encode(vg_saved_view_query($_GET),JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)).'"><input name="name" maxlength="100" required placeholder="현재 필터 이름"><button class="btn btn--sm btn--ghost">현재 보기 저장</button></form></div>';
}