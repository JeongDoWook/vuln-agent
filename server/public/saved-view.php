<?php
declare(strict_types=1);
require __DIR__.'/../src/auth.php';require __DIR__.'/../src/saved_views.php';vg_require_login();
if(($_SERVER['REQUEST_METHOD']??'')!=='POST'||!vg_csrf_check($_POST['csrf']??null)){http_response_code(400);exit;}
$page=(string)($_POST['page_code']??'');if(!isset(VG_SAVED_VIEW_PAGES[$page])){http_response_code(400);exit;}
$name=trim((string)($_POST['name']??''));$raw=json_decode((string)($_POST['query_json']??''),true);if($name===''||!is_array($raw)){http_response_code(400);exit;}
$u=vg_current_user();$query=vg_saved_view_query($raw);$pdo=vg_pdo();$pdo->prepare('INSERT INTO tb_saved_view(user_id,page_code,name,query_json) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE query_json=VALUES(query_json),is_deleted=0,deleted_at=NULL')->execute([$u['id'],$page,mb_strimwidth($name,0,100,''),json_encode($query,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)]);vg_log_activity($pdo,'SAVED_VIEW',null,'saved_view_save',$page.' · '.$name,null,null,'USER');header('Location: '.VG_SAVED_VIEW_PAGES[$page].($query?'?'.http_build_query($query):''),true,303);