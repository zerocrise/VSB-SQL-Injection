<?php
/**
 * ============================================================
 *  SECURE.PHP  –  VERSIONE PROTETTA CON PREPARED STATEMENTS
 *  Contromisure attive contro SQL Injection
 * ============================================================
 *
 *  Protezioni implementate:
 *   [P1] Prepared statements con parametri bind (mysqli)
 *   [P2] Validazione e sanificazione dell'input
 *   [P3] Errori generici (nessun dettaglio tecnico all'utente)
 *   [P4] Password confrontata tramite password_hash/verify
 *   [P5] Nessun campo sensibile esposto nell'output
 *   [P6] Utente DB con privilegi minimi
 *   [P7] Intestazioni di sicurezza HTTP
 * ============================================================
 */

// ── [P7] Intestazioni di sicurezza ──────────────────────────
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Content-Security-Policy: default-src 'self'");

// ── Configurazione DB ────────────────────────────────────────
define('DB_HOST', 'localhost');
define('DB_USER', 'sqli_user');   // [P6] utente con soli privilegi necessari
define('DB_PASS', 'sqli_pass');
define('DB_NAME', 'sqli_demo');

// ── Connessione con gestione errori sicura ───────────────────
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT); // eccezioni invece di warning
try {
    $conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    mysqli_set_charset($conn, 'utf8mb4');
} catch (Exception $e) {
    // [P3] All'utente: messaggio generico. In log: dettaglio reale.
    error_log("DB connection failed: " . $e->getMessage());
    die("<p>Servizio temporaneamente non disponibile.</p>");
}

// ── [P2] Funzione di validazione input ──────────────────────
function valida_stringa(string $input, int $max = 100): string {
    $input = trim($input);
    $input = strip_tags($input);
    if (mb_strlen($input) > $max) {
        $input = mb_substr($input, 0, $max);
    }
    return $input;
}

// ── Legge e valida l'input ───────────────────────────────────
$username = valida_stringa($_POST['username'] ?? '', 50);
$password = valida_stringa($_POST['password'] ?? '', 100);
$cerca    = valida_stringa($_POST['cerca']    ?? '', 50);

$login_msg = '';
$login_ok  = false;
$utente_loggato = null;

// ── LOGIN con Prepared Statement ────────────────────────────
if ($username !== '' && $password !== '' && isset($_POST['login'])) {

    /*
     * [P1] Il parametro "?" è un segnaposto.
     * mysqli_stmt_bind_param lega il valore reale SEPARATO dalla query.
     * Il motore SQL non può mai interpretare l'input come codice SQL.
     */
    $stmt = mysqli_prepare($conn,
        "SELECT id, username, email, ruolo, password
           FROM utenti
          WHERE username = ?
            AND attivo = 1
          LIMIT 1"
    );

    // "s" = tipo stringa
    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if ($row = mysqli_fetch_assoc($result)) {
        /*
         * [P4] In produzione le password vanno hashate con password_hash().
         * Qui confronto plain-text per semplicità didattica, ma la struttura
         * è quella corretta: confronto DOPO il fetch, non nella query WHERE.
         *
         * Produzione: if (password_verify($password, $row['password'])) { ... }
         */
        if ($password === $row['password']) {   // ← sostituire con password_verify in prod
            $login_ok = true;
            $utente_loggato = $row;
        }
    }

    mysqli_stmt_close($stmt);

    // [P3] Messaggio generico: non rivela se manca username o password
    $login_msg = $login_ok
        ? "✅ Benvenuto, " . htmlspecialchars($utente_loggato['username']) . "!"
        : "❌ Credenziali non valide.";
}

// ── RICERCA con Prepared Statement + LIKE sicuro ─────────────
$risultati_ricerca = [];

if (isset($_POST['ricerca']) && $cerca !== '') {

    $stmt2 = mysqli_prepare($conn,
        "SELECT id, prodotto, importo, data_ord
           FROM ordini
          WHERE prodotto LIKE ?
          LIMIT 20"
    );

    // [P1] Il "%" va nel valore, NON nella query → sicuro
    $like_param = '%' . $cerca . '%';
    mysqli_stmt_bind_param($stmt2, "s", $like_param);
    mysqli_stmt_execute($stmt2);
    $result2 = mysqli_stmt_get_result($stmt2);

    while ($r = mysqli_fetch_assoc($result2)) {
        $risultati_ricerca[] = $r;
    }

    mysqli_stmt_close($stmt2);
}

mysqli_close($conn);
?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <title>✅ Pagina Sicura</title>
    <style>
        body { font-family: sans-serif; max-width: 700px; margin: 2em auto; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 6px 12px; }
        th { background: #eee; }
        .ok  { color: green; }
        .err { color: orange; }
        .box { background: #f0fff0; border: 1px solid #9c9; padding: 1em;
               border-radius: 6px; margin-bottom: 1em; }
        .warn { background: #fffbe6; border: 1px solid #e6c; padding: .5em; font-size:.85em; }
    </style>
</head>
<body>

<h1>🔐 Login (SICURO – Prepared Statements)</h1>

<div class="box">
    <strong>Protezioni attive:</strong>
    <ul>
        <li>[P1] Prepared statements – input mai interpolato nella query</li>
        <li>[P2] Validazione lunghezza e strip_tags sull'input</li>
        <li>[P3] Nessun messaggio di errore tecnico all'utente</li>
        <li>[P4] Confronto password separato dalla query SQL</li>
        <li>[P5] Nessun campo sensibile nell'output</li>
    </ul>
</div>

<form method="POST">
    <label>Username: <input name="username" value="<?= htmlspecialchars($username) ?>"></label><br><br>
    <label>Password:
        <input type="password" name="password">
    </label><br><br>
    <button type="submit" name="login">Entra</button>
</form>

<?php if ($login_msg !== ''): ?>
    <p class="<?= $login_ok ? 'ok' : 'err' ?>"><?= $login_msg ?></p>
    <?php if ($login_ok): ?>
        <p>Ruolo: <strong><?= htmlspecialchars($utente_loggato['ruolo']) ?></strong>
           &nbsp;|&nbsp; Email: <?= htmlspecialchars($utente_loggato['email']) ?>
        </p>
        <!-- [P5] La password NON viene mai stampata -->
    <?php endif; ?>
<?php endif; ?>

<hr>
<h1>🔍 Ricerca prodotto (SICURA)</h1>

<form method="POST">
    <label>Prodotto: <input name="cerca" value="<?= htmlspecialchars($cerca) ?>"></label>
    <button type="submit" name="ricerca">Cerca</button>
</form>

<?php if (isset($_POST['ricerca']) && $cerca !== ''): ?>
    <p>Risultati per "<strong><?= htmlspecialchars($cerca) ?></strong>":</p>
    <?php if (empty($risultati_ricerca)): ?>
        <p>Nessun risultato trovato.</p>
    <?php else: ?>
        <table>
            <tr><th>ID</th><th>Prodotto</th><th>Importo (€)</th><th>Data</th></tr>
            <?php foreach ($risultati_ricerca as $r): ?>
            <tr>
                <td><?= (int)$r['id'] ?></td>
                <td><?= htmlspecialchars($r['prodotto']) ?></td>
                <td><?= htmlspecialchars($r['importo']) ?></td>
                <td><?= htmlspecialchars($r['data_ord']) ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
    <?php endif; ?>
    <p class="warn">
        ℹ️ Anche digitando <code>' OR '1'='1</code> o <code>' UNION SELECT...</code>
        il prepared statement non eseguirà mai codice SQL iniettato.
    </p>
<?php endif; ?>

</body>
</html>
