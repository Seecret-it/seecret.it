<?php
/**
 * API minimale pour Seecret.it self-hosted.
 * - POST : stocke un ciphertext opaque, retourne un id court.
 * - GET  : retourne le ciphertext puis le supprime immediatement (1 vue).
 * - Les secrets expires sont purges paresseusement a chaque appel.
 * - Rate-limit IP par fenetre de 1 minute (POST: 20, GET: 60).
 * - Le serveur ne voit JAMAIS la cle de dechiffrement
 *   (elle reste dans le # cote client, jamais transmis HTTP).
 */

declare(strict_types=1);

// ---------- Security headers ----------
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: interest-cohort=()');

// ---------- Config ----------
const DB_PATH            = __DIR__ . '/data/seecrets.sqlite';
const MAX_CIPHERTEXT_LEN = 65536;       // 64 KB
const MIN_EXPIRES_IN     = 60;          // 1 min
const MAX_EXPIRES_IN     = 30 * 86400;  // 30 jours
const DEFAULT_EXPIRES_IN = 86400;       // 1 jour
const MAX_TOTAL_SECRETS  = 50000;       // garde-fou disque
const RL_WINDOW          = 60;          // fenetre rate-limit (s)
const RL_POST_LIMIT      = 20;          // creations / min / IP
const RL_GET_LIMIT       = 60;          // lectures / min / IP

// ---------- Utilitaires ----------
function fail(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

function clientIp(): string {
    // REMOTE_ADDR uniquement. Si tu es derriere un reverse-proxy de confiance,
    // adapte ici (ex: $_SERVER['HTTP_X_FORWARDED_FOR']) en validant l'origine.
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Hash de l'IP avec un sel quotidien — pas d'IP en clair stockee.
 * Le sel tourne chaque jour, donc impossible de correler des activites
 * sur plusieurs jours meme avec acces au fichier.
 */
function ipKey(string $ip): string {
    return hash('sha256', $ip . '|' . date('Y-m-d') . '|seecret-rl');
}

function genId(): string {
    return rtrim(strtr(base64_encode(random_bytes(9)), '+/', '-_'), '=');
}

// ---------- DB ----------
function getDb(): PDO {
    if (!extension_loaded('pdo_sqlite')) {
        fail(500, 'Configuration serveur invalide.');
    }
    $dir = dirname(DB_PATH);
    if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
        fail(500, 'Stockage indisponible.');
    }
    if (!is_writable($dir)) {
        fail(500, 'Stockage indisponible.');
    }
    $first = !file_exists(DB_PATH);
    $db = new PDO('sqlite:' . DB_PATH);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec('PRAGMA journal_mode=WAL;');
    $db->exec('PRAGMA busy_timeout=3000;');
    if ($first) {
        @chmod(DB_PATH, 0640);
    }
    $db->exec('CREATE TABLE IF NOT EXISTS seecrets (
        id          TEXT PRIMARY KEY,
        ciphertext  TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL
    )');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_expires ON seecrets(expires_at)');
    $db->exec('CREATE TABLE IF NOT EXISTS rate_limit (
        ip_key       TEXT NOT NULL,
        action       TEXT NOT NULL,
        window_start INTEGER NOT NULL,
        count        INTEGER NOT NULL,
        PRIMARY KEY (ip_key, action, window_start)
    )');
    return $db;
}

function cleanup(PDO $db): void {
    $db->prepare('DELETE FROM seecrets   WHERE expires_at   < ?')->execute([time()]);
    $db->prepare('DELETE FROM rate_limit WHERE window_start < ?')->execute([time() - RL_WINDOW * 5]);
}

function checkRateLimit(PDO $db, string $action): void {
    $limit  = $action === 'POST' ? RL_POST_LIMIT : RL_GET_LIMIT;
    $bucket = intdiv(time(), RL_WINDOW) * RL_WINDOW;
    $key    = ipKey(clientIp());

    // UPSERT (SQLite >= 3.24). Incrementation atomique.
    $stmt = $db->prepare(
        'INSERT INTO rate_limit (ip_key, action, window_start, count) VALUES (?, ?, ?, 1)
         ON CONFLICT(ip_key, action, window_start) DO UPDATE SET count = count + 1'
    );
    $stmt->execute([$key, $action, $bucket]);

    $check = $db->prepare('SELECT count FROM rate_limit WHERE ip_key=? AND action=? AND window_start=?');
    $check->execute([$key, $action, $bucket]);
    $count = (int)$check->fetchColumn();

    if ($count > $limit) {
        header('Retry-After: ' . max(1, RL_WINDOW - (time() - $bucket)));
        fail(429, 'Trop de requetes. Reessayez dans une minute.');
    }
}

function checkCapacity(PDO $db): void {
    $count = (int)$db->query('SELECT COUNT(*) FROM seecrets')->fetchColumn();
    if ($count >= MAX_TOTAL_SECRETS) {
        fail(503, 'Service temporairement plein. Reessayez plus tard.');
    }
}

// ---------- Routing ----------
try {
    $db = getDb();
    cleanup($db);
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    if ($method === 'POST') {
        // CSRF mitigation : refuse les requetes cross-origin form-encoded
        $ctype = $_SERVER['CONTENT_TYPE'] ?? '';
        if (stripos($ctype, 'application/json') !== 0) {
            fail(415, 'Content-Type doit etre application/json');
        }

        checkRateLimit($db, 'POST');
        checkCapacity($db);

        $raw = file_get_contents('php://input');
        if (!$raw || strlen($raw) > MAX_CIPHERTEXT_LEN + 1024) {
            fail(413, 'Payload trop volumineux');
        }
        $input = json_decode($raw, true);
        if (!is_array($input)) fail(400, 'JSON invalide');

        $ct = $input['ciphertext'] ?? null;
        if (!is_string($ct) || $ct === '' || strlen($ct) > MAX_CIPHERTEXT_LEN) {
            fail(400, 'Ciphertext invalide');
        }
        if (!preg_match('#^[A-Za-z0-9_\-]+$#', $ct)) {
            fail(400, 'Format de ciphertext invalide');
        }

        $exp = (int)($input['expires_in'] ?? DEFAULT_EXPIRES_IN);
        if ($exp < MIN_EXPIRES_IN || $exp > MAX_EXPIRES_IN) {
            fail(400, 'expires_in hors limites');
        }

        $id = null;
        for ($i = 0; $i < 5; $i++) {
            $candidate = genId();
            try {
                $db->prepare('INSERT INTO seecrets (id, ciphertext, created_at, expires_at) VALUES (?, ?, ?, ?)')
                   ->execute([$candidate, $ct, time(), time() + $exp]);
                $id = $candidate;
                break;
            } catch (PDOException $e) {
                if (strpos($e->getMessage(), 'UNIQUE') === false) throw $e;
            }
        }
        if ($id === null) fail(500, 'Impossible d\'allouer un id');

        echo json_encode(['id' => $id, 'expires_at' => time() + $exp]);
        exit;
    }

    if ($method === 'GET') {
        checkRateLimit($db, 'GET');

        $id = $_GET['id'] ?? '';
        if (!is_string($id) || !preg_match('#^[A-Za-z0-9_\-]{8,32}$#', $id)) {
            fail(400, 'Id invalide');
        }

        // Atomique : prendre le lock immediatement puis SELECT + DELETE.
        $db->exec('BEGIN IMMEDIATE');
        try {
            $stmt = $db->prepare('SELECT ciphertext FROM seecrets WHERE id = ? AND expires_at >= ?');
            $stmt->execute([$id, time()]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                $db->exec('COMMIT');
                fail(404, 'Secret introuvable ou expire');
            }
            $db->prepare('DELETE FROM seecrets WHERE id = ?')->execute([$id]);
            $db->exec('COMMIT');
        } catch (Throwable $e) {
            $db->exec('ROLLBACK');
            throw $e;
        }
        echo json_encode(['ciphertext' => $row['ciphertext']]);
        exit;
    }

    if ($method === 'OPTIONS') {
        // Preflight CORS — meme origine seulement, on refuse explicitement.
        http_response_code(405);
        header('Allow: GET, POST');
        exit;
    }

    fail(405, 'Methode non autorisee');
} catch (Throwable $e) {
    // Log cote serveur mais ne JAMAIS exposer le detail au client.
    error_log('[seecret-api] ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    fail(500, 'Erreur serveur');
}
