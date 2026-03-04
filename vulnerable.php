<?php
/**
 * ============================================================
 *  VULNERABLE.PHP  –  VERSIONE INTENZIONALMENTE VULNERABILE
 *  SOLO SCOPO DIDATTICO – NON USARE IN PRODUZIONE
 * ============================================================
 *
 *  Vulnerabilità presenti (intenzionali):
 *   [V1] Input utente concatenato direttamente nella query
 *   [V2] Nessuna sanitizzazione / validazione dell'input
 *   [V3] Errori MySQL esposti all'utente (information disclosure)
 *   [V4] Nessuna gestione delle sessioni / autenticazione robusta
 *   [V5] Visualizzazione di tutti i campi (comprese password)
 * ============================================================
 */

// ── Configurazione DB ────────────────────────────────────────
define('DB_HOST', 'localhost');
define('DB_USER', 'root');       // [V] utente privilegiato
define('DB_PASS', '');
define('DB_NAME', 'sqli_demo');

$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);

if (!$conn) {
    // [V3] Espone dettagli interni dell'errore
    die("Connessione fallita: " . mysqli_connect_error());
}

// ── Legge l'input via POST ────────────────────────────────────
$username = $_POST['username'] ?? '';   // [V2] nessuna validazione
$password = $_POST['password'] ?? '';
$cerca    = $_POST['cerca']    ?? '';

// ── LOGIN ─────────────────────────────────────────────────────
if (isset($_POST['login'])) {
    // [V1]  *** PUNTO DI INIEZIONE ***
    $query = "SELECT * FROM utenti
               WHERE username = '$username'
                 AND password = '$password'";

    echo "<h2>⚠️  File VULNERABILE – solo uso didattico</h2>";
    echo "<pre style='color:gray'>Query eseguita:\n$query\n</pre>";

    $result = mysqli_query($conn, $query);

    if ($result === false) {
        // [V3] Espone l'errore SQL completo
        echo "<p style='color:red'>Errore SQL: " . mysqli_error($conn) . "</p>";
    } elseif (mysqli_num_rows($result) > 0) {
        echo "<p style='color:green'>✅ Login riuscito!</p>";
        echo "<table border='1' cellpadding='6'>";
        echo "<tr><th>ID</th><th>Username</th><th>Password</th>
                  <th>Email</th><th>Ruolo</th></tr>";
        while ($row = mysqli_fetch_assoc($result)) {
            // [V5] Stampa anche la password in chiaro
            echo "<tr>
                    <td>{$row['id']}</td>
                    <td>{$row['username']}</td>
                    <td style='color:red'>{$row['password']}</td>
                    <td>{$row['email']}</td>
                    <td>{$row['ruolo']}</td>
                  </tr>";
        }
        echo "</table>";
    } else {
        echo "<p style='color:orange'>❌ Credenziali non valide.</p>";
    }
}

// ── RICERCA PRODOTTI ──────────────────────────────────────────
if (isset($_POST['ricerca']) && $cerca !== '') {
    // [V1] Secondo punto di iniezione
    $q2 = "SELECT id, prodotto, importo, data_ord
             FROM ordini
            WHERE prodotto LIKE '%$cerca%'";

    echo "<hr><h3>Risultati ricerca prodotto: \"$cerca\"</h3>";
    echo "<pre style='color:gray'>Query:\n$q2\n</pre>";

    $r2 = mysqli_query($conn, $q2);
    if ($r2 === false) {
        echo "<p style='color:red'>Errore: " . mysqli_error($conn) . "</p>";
    } else {
        echo "<table border='1' cellpadding='6'>";
        echo "<tr><th>ID</th><th>Prodotto</th><th>Importo (€)</th><th>Data</th></tr>";
        while ($row = mysqli_fetch_assoc($r2)) {
            echo "<tr>
                    <td>{$row['id']}</td>
                    <td>{$row['prodotto']}</td>
                    <td>{$row['importo']}</td>
                    <td>{$row['data_ord']}</td>
                  </tr>";
        }
        echo "</table>";
    }
}

mysqli_close($conn);
?>

<!DOCTYPE html>
<html lang="it">
<head><meta charset="UTF-8"><title>⚠️ Pagina Vulnerabile</title></head>
<body>
<h1>🔓 Login (VULNERABILE)</h1>
<form method="POST">
    <label>Username: <input name="username" value="<?= htmlspecialchars($username) ?>"></label><br><br>
    <label>Password: <input name="password" value="<?= htmlspecialchars($password) ?>"></label><br><br>
    <button type="submit" name="login">Entra</button>
</form>

<hr>

<h1>🔍 Ricerca prodotto (VULNERABILE)</h1>
<form method="POST">
    <label>Prodotto: <input name="cerca" value="<?= htmlspecialchars($cerca) ?>"></label>
    <button type="submit" name="ricerca">Cerca</button>
</form>


</body>
</html>
