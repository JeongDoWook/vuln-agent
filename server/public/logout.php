<?php
declare(strict_types=1);

require __DIR__ . '/../src/auth.php';
vg_logout();
header('Location: /login.php');
