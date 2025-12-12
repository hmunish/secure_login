<?php
if (preg_match('/private\.pem$/', $_SERVER['REQUEST_URI'])) {
    http_response_code(403);
    exit("Forbidden");
}
if ($_SERVER['REQUEST_URI'] === '/public.pem') {
    header("Content-Type: application/x-pem-file");
    readfile(__DIR__ . '/public.pem');
    exit;
}
if ($_SERVER['REQUEST_URI'] === '/api.php') {
    require __DIR__ . '/api.php';
    exit;
}
$publicPath = __DIR__ . '/public' . $_SERVER['REQUEST_URI'];
if (file_exists($publicPath) && !is_dir($publicPath)) {
    return false;
}
require __DIR__ . '/public/index.html';