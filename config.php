<?php
declare(strict_types=1);

date_default_timezone_set('Asia/Yekaterinburg');

const APP_NAME = 'Практика.Цифра';
const APP_BASE_URL = 'https://mincifra-practica.ru';
const DB_PATH = __DIR__ . '/data/practice.sqlite';
const UPLOAD_DIR = __DIR__ . '/uploads';
const MAX_UPLOAD_SIZE = 10 * 1024 * 1024;
const PASSWORD_RESET_TTL = 3600;
const LOGIN_RATE_LIMIT = 10;
const LOGIN_RATE_WINDOW = 900;
const RESET_RATE_LIMIT = 5;
const RESET_RATE_WINDOW = 3600;
const POST_RATE_LIMIT = 80;
const POST_RATE_WINDOW = 60;
const MAIL_FROM_EMAIL = 'no-reply@mincifra-practica.ru';
const MAIL_FROM_NAME = 'Практика.Цифра';
const SMTP_HOST = 'mail.hosting.reg.ru';
const SMTP_PORT = 465;
const SMTP_SECURE = 'ssl';
const SMTP_TIMEOUT = 20;

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params([
        'httponly' => true,
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'samesite' => 'Lax',
    ]);
    session_start();
}

if (!headers_sent()) {
    header('X-Frame-Options: SAMEORIGIN');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
}

foreach ([dirname(DB_PATH), UPLOAD_DIR] as $directory) {
    if (!is_dir($directory)) {
        mkdir($directory, 0775, true);
    }
}

$db = new PDO('sqlite:' . DB_PATH);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$db->exec('PRAGMA foreign_keys = ON');

function init_database(PDO $db): void
{
    $db->exec(<<<SQL
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'mentor', 'intern')),
            mentor_status TEXT NOT NULL DEFAULT 'approved' CHECK(mentor_status IN ('approved', 'pending')),
            phone TEXT DEFAULT '',
            department TEXT DEFAULT '',
            position TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS intern_profiles (
            user_id INTEGER PRIMARY KEY,
            university TEXT NOT NULL,
            specialty TEXT NOT NULL,
            course INTEGER NOT NULL,
            group_name TEXT DEFAULT '',
            practice_topic TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            mentor_id INTEGER,
            status TEXT NOT NULL DEFAULT 'Практика назначена',
            final_grade TEXT DEFAULT '',
            conclusion TEXT DEFAULT '',
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (mentor_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            intern_id INTEGER NOT NULL,
            mentor_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            due_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Новое',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (intern_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (mentor_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            intern_id INTEGER NOT NULL,
            task_id INTEGER,
            title TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            original_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'На проверке',
            mentor_comment TEXT DEFAULT '',
            uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (intern_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS diary_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            intern_id INTEGER NOT NULL,
            entry_date TEXT NOT NULL,
            work_done TEXT NOT NULL,
            hours INTEGER NOT NULL DEFAULT 8,
            status TEXT NOT NULL DEFAULT 'На проверке',
            mentor_comment TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (intern_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token_hash);
        CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);

        CREATE TABLE IF NOT EXISTS rate_limits (
            key TEXT PRIMARY KEY,
            attempts INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
    SQL);

    $columns = $db->query("PRAGMA table_info(users)")->fetchAll();
    $hasMentorStatus = false;
    foreach ($columns as $column) {
        if (($column['name'] ?? '') === 'mentor_status') {
            $hasMentorStatus = true;
            break;
        }
    }
    if (!$hasMentorStatus) {
        $db->exec("ALTER TABLE users ADD COLUMN mentor_status TEXT NOT NULL DEFAULT 'approved' CHECK(mentor_status IN ('approved', 'pending'))");
        $db->exec("UPDATE users SET mentor_status = 'approved'");
    }

    $count = (int)$db->query("SELECT COUNT(*) FROM users WHERE role IN ('admin', 'mentor')")->fetchColumn();
    if ($count === 0) {
        $insert = $db->prepare('INSERT INTO users (full_name, email, password_hash, role, phone, department, position) VALUES (?, ?, ?, ?, ?, ?, ?)');
        $password = password_hash('demo123', PASSWORD_DEFAULT);
        $insert->execute(['Администратор системы', 'admin@practice.local', $password, 'admin', '+7 (3532) 00-00-01', 'Отдел цифровизации', 'Администратор']);
        $insert->execute(['Анна Сергеевна Волкова', 'mentor@practice.local', $password, 'mentor', '+7 (3532) 00-00-02', 'Отдел информационных систем', 'Главный специалист']);
        $insert->execute(['Михаил Олегович Соколов', 'mentor2@practice.local', $password, 'mentor', '+7 (3532) 00-00-03', 'Отдел связи', 'Ведущий консультант']);
    }
}

init_database($db);

function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

function csrf_check(?string $token): bool
{
    return is_string($token) && $token !== '' && isset($_SESSION['csrf_token']) && hash_equals((string)$_SESSION['csrf_token'], $token);
}

function rotate_csrf_token(): void
{
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function user(): ?array
{
    return $_SESSION['user'] ?? null;
}

function redirect(string $url = 'index.php'): never
{
    header('Location: ' . $url);
    exit;
}

function flash(string $message, string $type = 'success'): void
{
    $_SESSION['flash'] = ['message' => $message, 'type' => $type];
}

function require_role(string ...$roles): array
{
    $current = user();
    if (!$current || !in_array($current['role'], $roles, true)) {
        flash('Для доступа к разделу необходимо войти в систему.', 'error');
        redirect('index.php?page=login');
    }
    return $current;
}

function role_name(string $role): string
{
    return ['admin' => 'Администратор', 'mentor' => 'Руководитель', 'intern' => 'Практикант'][$role] ?? $role;
}

function progress(PDO $db, int $internId): int
{
    $stmt = $db->prepare("SELECT COUNT(*) total, SUM(CASE WHEN status = 'Выполнено' THEN 1 ELSE 0 END) done FROM tasks WHERE intern_id = ?");
    $stmt->execute([$internId]);
    $row = $stmt->fetch();
    return (int)$row['total'] === 0 ? 0 : (int)round(((int)$row['done'] / (int)$row['total']) * 100);
}

function fetch_all(PDO $db, string $sql, array $params = []): array
{
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function fetch_one(PDO $db, string $sql, array $params = []): ?array
{
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $row = $stmt->fetch();
    return $row ?: null;
}

function client_ip(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    return is_string($ip) && preg_match('/^[a-f0-9:.]+$/i', $ip) ? $ip : 'unknown';
}

function rate_limit_key(string $scope, string $subject = ''): string
{
    return $scope . ':' . hash('sha256', client_ip() . '|' . strtolower($subject));
}

function rate_limit_check(PDO $db, string $key, int $limit, int $window): bool
{
    $now = time();
    $db->prepare('DELETE FROM rate_limits WHERE expires_at <= ?')->execute([$now]);
    $stmt = $db->prepare('SELECT attempts, expires_at FROM rate_limits WHERE key = ?');
    $stmt->execute([$key]);
    $row = $stmt->fetch();
    if (!$row) {
        $db->prepare('INSERT INTO rate_limits (key, attempts, expires_at) VALUES (?, 1, ?)')->execute([$key, $now + $window]);
        return true;
    }
    if ((int)$row['attempts'] >= $limit) {
        return false;
    }
    $db->prepare('UPDATE rate_limits SET attempts = attempts + 1 WHERE key = ?')->execute([$key]);
    return true;
}

function rate_limit_clear(PDO $db, string $key): void
{
    $db->prepare('DELETE FROM rate_limits WHERE key = ?')->execute([$key]);
}

function app_url(string $path): string
{
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $basePath = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
    $basePath = $basePath === '.' ? '' : $basePath;
    if (preg_match('/^(?:localhost|127\.0\.0\.1)(?::\d+)?$/', $host)) {
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        return $scheme . '://' . $host . $basePath . '/' . ltrim($path, '/');
    }
    return rtrim(APP_BASE_URL, '/') . $basePath . '/' . ltrim($path, '/');
}

function mail_subject(string $subject): string
{
    return '=?UTF-8?B?' . base64_encode($subject) . '?=';
}

function mail_settings(): array
{
    $settings = [
        'host' => getenv('SMTP_HOST') ?: SMTP_HOST,
        'port' => (int)(getenv('SMTP_PORT') ?: SMTP_PORT),
        'secure' => getenv('SMTP_SECURE') ?: SMTP_SECURE,
        'username' => getenv('SMTP_USERNAME') ?: '',
        'password' => getenv('SMTP_PASSWORD') ?: '',
        'from_email' => getenv('SMTP_FROM_EMAIL') ?: MAIL_FROM_EMAIL,
        'from_name' => getenv('SMTP_FROM_NAME') ?: MAIL_FROM_NAME,
    ];
    $localConfig = __DIR__ . '/mail_config.php';
    if (is_file($localConfig)) {
        $custom = require $localConfig;
        if (is_array($custom)) {
            $settings = array_merge($settings, array_intersect_key($custom, $settings));
        }
    }
    if ($settings['from_email'] === '' && $settings['username'] !== '') {
        $settings['from_email'] = $settings['username'];
    }
    return $settings;
}

function mail_log(string $message): void
{
    $line = '[' . date('Y-m-d H:i:s') . '] ' . $message . PHP_EOL;
    @file_put_contents(dirname(DB_PATH) . '/mail-errors.log', $line, FILE_APPEND | LOCK_EX);
}

function smtp_read($connection): string
{
    $response = '';
    while (($line = fgets($connection, 515)) !== false) {
        $response .= $line;
        if (isset($line[3]) && $line[3] === ' ') {
            break;
        }
    }
    return $response;
}

function smtp_expect($connection, array $codes, string $context): string
{
    $response = smtp_read($connection);
    $code = (int)substr($response, 0, 3);
    if (!in_array($code, $codes, true)) {
        throw new RuntimeException($context . ': ' . trim($response));
    }
    return $response;
}

function smtp_command($connection, string $command, array $codes, string $context): string
{
    fwrite($connection, $command . "\r\n");
    return smtp_expect($connection, $codes, $context);
}

function smtp_normalize_lines(string $text): string
{
    $text = str_replace(["\r\n", "\r"], "\n", $text);
    $lines = explode("\n", $text);
    foreach ($lines as &$line) {
        if (str_starts_with($line, '.')) {
            $line = '.' . $line;
        }
    }
    return implode("\r\n", $lines);
}

function smtp_send(array $settings, string $to, string $subject, string $body): bool
{
    if ($settings['username'] === '' || $settings['password'] === '') {
        mail_log('SMTP credentials are not configured.');
        return false;
    }

    $host = (string)$settings['host'];
    $port = (int)$settings['port'];
    $secure = strtolower((string)$settings['secure']);
    $remote = ($secure === 'ssl' ? 'ssl://' : '') . $host . ':' . $port;
    $connection = @stream_socket_client($remote, $errorNumber, $errorText, SMTP_TIMEOUT, STREAM_CLIENT_CONNECT);
    if (!$connection) {
        mail_log('SMTP connection failed: ' . $errorNumber . ' ' . $errorText);
        return false;
    }

    stream_set_timeout($connection, SMTP_TIMEOUT);
    $serverName = parse_url(APP_BASE_URL, PHP_URL_HOST) ?: 'mincifra-practica.ru';
    $fromEmail = (string)$settings['from_email'];
    $fromName = (string)$settings['from_name'];

    try {
        smtp_expect($connection, [220], 'SMTP greeting');
        smtp_command($connection, 'EHLO ' . $serverName, [250], 'SMTP EHLO');
        if ($secure === 'tls') {
            smtp_command($connection, 'STARTTLS', [220], 'SMTP STARTTLS');
            if (!stream_socket_enable_crypto($connection, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                throw new RuntimeException('SMTP TLS negotiation failed');
            }
            smtp_command($connection, 'EHLO ' . $serverName, [250], 'SMTP EHLO TLS');
        }
        smtp_command($connection, 'AUTH LOGIN', [334], 'SMTP AUTH LOGIN');
        smtp_command($connection, base64_encode((string)$settings['username']), [334], 'SMTP username');
        smtp_command($connection, base64_encode((string)$settings['password']), [235], 'SMTP password');
        smtp_command($connection, 'MAIL FROM:<' . $fromEmail . '>', [250], 'SMTP MAIL FROM');
        smtp_command($connection, 'RCPT TO:<' . $to . '>', [250, 251], 'SMTP RCPT TO');
        smtp_command($connection, 'DATA', [354], 'SMTP DATA');

        $headers = [
            'From: ' . mail_subject($fromName) . ' <' . $fromEmail . '>',
            'To: <' . $to . '>',
            'Subject: ' . mail_subject($subject),
            'Date: ' . date(DATE_RFC2822),
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
        ];
        $message = implode("\r\n", $headers) . "\r\n\r\n" . smtp_normalize_lines($body) . "\r\n.";
        smtp_command($connection, $message, [250], 'SMTP message body');
        smtp_command($connection, 'QUIT', [221, 250], 'SMTP QUIT');
        fclose($connection);
        return true;
    } catch (Throwable $exception) {
        mail_log('SMTP send failed to ' . $to . ': ' . $exception->getMessage());
        fclose($connection);
        return false;
    }
}

function send_password_reset_email(string $email, string $name, string $resetLink): bool
{
    $subject = 'Восстановление пароля на сайте ' . APP_NAME;
    $body = "Здравствуйте, {$name}!\n\n"
        . "Для вашего аккаунта на сайте " . APP_NAME . " запрошено восстановление пароля.\n"
        . "Перейдите по ссылке и задайте новый пароль:\n\n"
        . $resetLink . "\n\n"
        . "Ссылка действует 1 час. Если вы не запрашивали восстановление, просто проигнорируйте это письмо.\n\n"
        . "С уважением,\n"
        . APP_NAME;

    $settings = mail_settings();
    if (smtp_send($settings, $email, $subject, $body)) {
        return true;
    }

    $fromEmail = $settings['from_email'] ?: MAIL_FROM_EMAIL;
    $fromName = mail_subject($settings['from_name'] ?: MAIL_FROM_NAME);
    $headers = [
        'From: ' . $fromName . ' <' . $fromEmail . '>',
        'Reply-To: ' . $fromEmail,
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit',
    ];

    $sent = @mail($email, mail_subject($subject), $body, implode("\r\n", $headers), '-f ' . $fromEmail);
    if (!$sent) {
        mail_log('PHP mail fallback failed to ' . $email . '. Password reset link was not written to logs.');
    }
    return $sent;
}
