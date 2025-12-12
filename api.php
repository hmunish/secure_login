<?php
declare(strict_types=1);
require __DIR__ . "/vendor/autoload.php";
use Dotenv\Dotenv;
header("Content-Type: application/json");
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();
function envv($k)
{
    return $_ENV[$k] ?? null;
}
$pdo = new PDO("mysql:host=" . envv("DB_HOST") . ";dbname=" . envv("DB_NAME") . ";charset=utf8mb4", envv("DB_USER"), envv("DB_PASS"), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$privateKey = openssl_pkey_get_private(file_get_contents(envv("PRIVATE_KEY_PATH")));
function response($a)
{
    echo json_encode($a);
    exit;
}
function decryptHybrid($payloadB64)
{
    global $privateKey;
    $raw = base64_decode($payloadB64, true);
    if (!$raw)
        return false;
    $packet = json_decode($raw, true);
    if (!isset($packet["key"], $packet["iv"], $packet["data"]))
        return false;
    $aesKeyEncrypted = base64_decode($packet["key"]);
    $iv = base64_decode($packet["iv"]);
    $cipher = base64_decode($packet["data"]);
    if (!openssl_private_decrypt($aesKeyEncrypted, $aesKeyRaw, $privateKey, OPENSSL_PKCS1_OAEP_PADDING))
        return false;
    $tag = substr($cipher, -16);
    $ciphertext = substr($cipher, 0, -16);
    return openssl_decrypt($ciphertext, "aes-256-gcm", $aesKeyRaw, OPENSSL_RAW_DATA, $iv, $tag);
}
function recordFail($pdo, $ip)
{
    $pdo->prepare("INSERT INTO ip_failures(ip,attempts,last_failed) VALUES(?,1,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE attempts=attempts+1,last_failed=UTC_TIMESTAMP()")->execute([$ip]);
}
function ipBlocked($pdo, $ip)
{
    $s = $pdo->prepare("SELECT attempts FROM ip_failures WHERE ip=?");
    $s->execute([$ip]);
    $r = $s->fetch();
    return $r && $r["attempts"] > 50;
}
$action = $_POST["action"] ?? "";
session_start();

if ($action === "login") {
    $ip = $_SERVER["REMOTE_ADDR"];
    if (ipBlocked($pdo, $ip))
        response(["success" => false, "message" => "Too many attempts"]);
    if (empty($_POST["payload"]))
        response(["success" => false, "message" => "Missing payload"]);
    $plaintext = decryptHybrid($_POST["payload"]);
    if (!$plaintext) {
        recordFail($pdo, $ip);
        response(["success" => false, "message" => "Invalid encrypted data"]);
    }
    $plaintext = trim($plaintext);
    $data = json_decode($plaintext, true);
    if (!$data)
        response(["success" => false, "message" => "Invalid payload"]);
    $u = trim($data["username"]);
    $p = $data["password"];
    if (strlen($u) < 3 || strlen($p) < 8)
        response(["success" => false, "message" => "Validation failed"]);
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username=?");
    $stmt->execute([$u]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        recordFail($pdo, $ip);
        response(["success" => false, "message" => "Invalid credentials"]);
    }
    if ($user["lockout_until"] && strtotime($user["lockout_until"]) > time())
        response(["success" => false, "message" => "Account locked"]);
    if (!password_verify($p, $user["password_hash"])) {
        $fa = $user["failed_attempts"] + 1;
        $lock = null;
        if ($fa >= (int) envv("LOCKOUT_THRESHOLD")) {
            $lock = date("Y-m-d H:i:s", strtotime("+" . envv("LOCKOUT_MINUTES") . " minutes"));
            $fa = 0;
        }
        $pdo->prepare("UPDATE users SET failed_attempts=?,lockout_until=? WHERE id=?")->execute([$fa, $lock, $user["id"]]);
        recordFail($pdo, $ip);
        response(["success" => false, "message" => "Invalid credentials"]);
    }
    $pdo->prepare("UPDATE users SET failed_attempts=0,lockout_until=NULL WHERE id=?")->execute([$user["id"]]);
    session_regenerate_id(true);
    $_SESSION["user_id"] = $user["id"];
    response(["success" => true, "first_name" => $user["first_name"], "last_name" => $user["last_name"]]);
}
if ($action === "profile") {
    if (!isset($_SESSION["user_id"]))
        response(["success" => false]);
    $stmt = $pdo->prepare("SELECT first_name,last_name FROM users WHERE id=?");
    $stmt->execute([$_SESSION["user_id"]]);
    $u = $stmt->fetch(PDO::FETCH_ASSOC);
    response(["success" => true, "first_name" => $u["first_name"], "last_name" => $u["last_name"]]);
}
if ($action === "logout") {
    session_destroy();
    response(["success" => true]);
}
response(["success" => false, "message" => "Unknown action"]);