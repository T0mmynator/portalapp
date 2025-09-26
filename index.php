<?php
session_start();
$message = "";

// Veritabanı bilgileri
$servername = "127.0.0.1";
$dbusername = "user";
$dbpassword = "password";
$dbname     = "portal_db";

// MySQLi hata raporlama
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

$ip = $_SERVER['REMOTE_ADDR'];

try {
    $conn = new mysqli($servername, $dbusername, $dbpassword, $dbname);
    $conn->set_charset("utf8mb4");

    // WHITELIST KONTROLÜ
    if (!isset($_SESSION['username'])) {
        $stmt = $conn->prepare("SELECT * FROM whitelist WHERE ip=? LIMIT 1");
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $_SESSION['username'] = "whitelist_user";
            header("Location: welcome.php");
            exit();
        }
        $stmt->close();
    }

    // FORM İŞLEMLERİ
    $form_type = $_POST['form_type'] ?? '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && $form_type) {
        $user = trim($_POST['username'] ?? '');
        $pass = trim($_POST['password'] ?? '');

        if ($form_type === "login") {
            $stmt = $conn->prepare("SELECT password FROM users WHERE username=? LIMIT 1");
            $stmt->bind_param("s", $user);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result && $result->num_rows > 0) {
                $row = $result->fetch_assoc();
                if (password_verify($pass, $row['password'])) {
                    $_SESSION['username'] = $user;
                    $user_ip = $_SERVER['REMOTE_ADDR'];

                    // IPTABLES KURALLARI
                    $checkRule = "sudo iptables -C FORWARD -s $user_ip -j ACCEPT 2>/dev/null";
                    if (shell_exec($checkRule) === null) {
                        shell_exec("sudo iptables -A FORWARD -s $user_ip -j ACCEPT");
                        shell_exec("sudo iptables -A FORWARD -d $user_ip -j ACCEPT");
                        shell_exec("sudo iptables -t nat -C POSTROUTING -s $user_ip -o wlan0 -j MASQUERADE 2>/dev/null || sudo iptables -t nat -A POSTROUTING -s $user_ip -o wlan0 -j MASQUERADE");
                    }

                    // MAC ADRESİ AL ve whitelist DB'ye ekle
                    $arp_table = @shell_exec("arp -n $user_ip | awk '{print $3}'");
                    $user_mac = trim($arp_table ?? '');
		    // dnsmasq VIP tag ekleme
		    // $raw = "dhcp-host=HWaddress 1e:bf:83:25:66:6a,set:vip"; // örnek girdin
		    // if (preg_match('/([0-9a-f]{2}(?::[0-9a-f]{2}){5})/i', $raw, $m)) {
		    // 	$mac = strtolower($m[1]); // küçük harf, standart format
		    // 	$line = "dhcp-host={$mac},set:vip\n";
		    //	file_put_contents('/etc/dnsmasq.d/vip.conf', $line, FILE_APPEND | LOCK_EX);
			// reload
		    //	shell_exec('sudo systemctl restart dnsmasq');
		   //  } else {
			// MAC bulunamadı — hata logla
		    //	error_log("MAC bulunamadı: " . $raw);
		    // }






		    if ($user_mac) {
                        $stmt2 = $conn->prepare("INSERT INTO whitelist (ip, mac) VALUES (?, ?) ON DUPLICATE KEY UPDATE mac=?");
                        $stmt2->bind_param("sss", $user_ip, $user_mac, $user_mac);
                        $stmt2->execute();
                        $stmt2->close();
                    }

                    header("Location: welcome.php");
                    exit();
                } else {
                    $message = "Hatalı şifre!";
                }
            } else {
                $message = "Kullanıcı bulunamadı!";
            }
            $stmt->close();

        } elseif ($form_type === "register") {
            if (empty($user) || empty($pass)) {
                $message = "Kullanıcı adı ve şifre boş olamaz!";
            } else {
                $hash = password_hash($pass, PASSWORD_DEFAULT);
                $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
                $stmt->bind_param("ss", $user, $hash);
                if ($stmt->execute()) {
                    $message = "Kayıt başarılı! Giriş yapabilirsiniz.";
                } else {
                    $message = "Kayıt başarısız: Kullanıcı adı mevcut olabilir.";
                }
                $stmt->close();
            }
        }
    }

    $conn->close();
} catch (Exception $e) {
    error_log($e->getMessage());
    die("Bir hata oluştu: " . htmlspecialchars($e->getMessage()));
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>Login / Register</title>
<style>
body { font-family: Arial; background:#f4f4f4; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }
.container { background:#fff; padding:20px; border-radius:8px; box-shadow:0 2px 6px rgba(0,0,0,0.2); width:300px; }
input { display:block; margin:10px 0; padding:10px; width:100%; border:1px solid #ccc; border-radius:4px; }
button { padding:10px; width:100%; background:#007BFF; color:#fff; border:none; border-radius:4px; cursor:pointer; }
button:hover { background:#0056b3; }
.error { color:red; text-align:center; }
.success { color:green; text-align:center; }
h2 { text-align:center; }
</style>
</head>
<body>
<div class="container">
    <h2>Login</h2>
    <form method="POST">
        <input type="hidden" name="form_type" value="login">
        <input type="text" name="username" placeholder="Kullanıcı adı" required>
        <input type="password" name="password" placeholder="Şifre" required>
        <button type="submit">Giriş Yap</button>
    </form>

    <h2>Register</h2>
    <form method="POST">
        <input type="hidden" name="form_type" value="register">
        <input type="text" name="username" placeholder="Yeni kullanıcı adı" required>
        <input type="password" name="password" placeholder="Yeni şifre" required>
        <button type="submit">Kayıt Ol</button>
    </form>

    <?php if($message): ?>
        <p class="<?= $form_type === 'register' ? 'success' : 'error' ?>"><?= htmlspecialchars($message) ?></p>
    <?php endif; ?>
</div>
</body>
</html>