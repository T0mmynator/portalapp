<?php
session_start();

$ip = $_SERVER['REMOTE_ADDR'];

// --- Veritabanı bağlantısı ve whitelist'ten silme ---
$servername = "127.0.0.1";
$dbusername = "user";
$dbpassword = "password";
$dbname     = "portal_db";

$conn = new mysqli($servername, $dbusername, $dbpassword, $dbname);
$conn->set_charset("utf8mb4");

if ($conn->connect_error) {
    die("DB bağlantısı başarısız: " . $conn->connect_error);
}

$stmt = $conn->prepare("DELETE FROM whitelist WHERE ip=?");
$stmt->bind_param("s",$ip);
$stmt->execute();
$stmt->close();

// --- iptables temizlik ---
// IP’ye ait tüm kuralları bul ve sil
$escapedIp = escapeshellarg($ip);

// Filter table (FORWARD, INPUT, OUTPUT)
$rules = shell_exec("sudo iptables -S | grep $escapedIp");
$rules = explode("\n", trim($rules));

foreach ($rules as $rule) {
    if ($rule) {
        $deleteRule = preg_replace('/^-A/', '-D', $rule, 1);
        shell_exec("sudo iptables $deleteRule");
    }
}

// NAT table (POSTROUTING, PREROUTING)
$natRules = shell_exec("sudo iptables -t nat -S | grep $escapedIp");
$natRules = explode("\n", trim($natRules));

foreach ($natRules as $rule) {
    if ($rule) {
        $deleteRule = preg_replace('/^-A/', '-D', $rule, 1);
        shell_exec("sudo iptables -t nat $deleteRule");
    }
}

// --- Session temizliği ---
if (isset($_SESSION['username'])) {
    session_unset();
    session_destroy();
}

header("Location: index.php");
exit();
?>