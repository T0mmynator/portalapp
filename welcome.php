<?php
session_start();
if (!isset($_SESSION['username'])) {
    header("Location: index.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Hoşgeldiniz</title>
</head>
<body>
    <h1>Hoşgeldin <?php echo htmlspecialchars($_SESSION['username']); ?> 🎉</h1>
    <a href="logout.php">Çıkış Yap</a>
</body>
</html>