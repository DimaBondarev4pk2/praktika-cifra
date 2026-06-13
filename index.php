<?php
declare(strict_types=1);
require __DIR__ . '/config.php';

$action = $_POST['action'] ?? '';
if ($action === '' && ($_GET['action'] ?? '') === 'download') {
    $action = 'download';
}

function action_redirect_target(string $action): string
{
    return match ($action) {
        'register' => 'index.php?page=register',
        'login' => 'index.php?page=login',
        'request_password_reset' => 'index.php?page=forgot',
        'reset_password' => 'index.php?page=forgot',
        'create_task', 'task_status' => 'index.php?page=tasks',
        'upload_report', 'review_report' => 'index.php?page=reports',
        'add_diary', 'review_diary' => 'index.php?page=diary',
        'update_profile' => 'index.php?page=profile',
        'assign_mentor', 'assign_bulk' => 'index.php?page=assignments',
        'finalize' => 'index.php?page=interns',
        default => user() ? 'index.php?page=dashboard' : 'index.php?page=login',
    };
}

function short_name(string $fullName): string
{
    $parts = preg_split('/\s+/u', trim($fullName));
    return $parts[0] ?? $fullName;
}

function greeting_text(?int $hour = null): string
{
    $hour ??= (int)date('G');
    if ($hour >= 5 && $hour < 12) {
        return 'Доброе утро';
    }
    if ($hour >= 12 && $hour < 18) {
        return 'Добрый день';
    }
    if ($hour >= 18 && $hour < 23) {
        return 'Добрый вечер';
    }
    return 'Доброй ночи';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!rate_limit_check($db, rate_limit_key('post'), POST_RATE_LIMIT, POST_RATE_WINDOW)) {
        flash('Слишком много запросов. Подождите минуту и попробуйте снова.', 'error');
        redirect(action_redirect_target($action));
    }
    if ($action === '' || !csrf_check($_POST['csrf_token'] ?? null)) {
        flash('Сессия формы устарела. Обновите страницу и повторите действие.', 'error');
        redirect(action_redirect_target($action));
    }
}

if ($action === 'register') {
    $required = ['full_name', 'email', 'password', 'university', 'specialty', 'course', 'practice_topic', 'start_date', 'end_date', 'mentor_id'];
    foreach ($required as $field) {
        if (trim((string)($_POST[$field] ?? '')) === '') {
            flash('Заполните все обязательные поля.', 'error');
            redirect('index.php?page=register');
        }
    }
    if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL) || strlen($_POST['password']) < 8) {
        flash('Проверьте email. Пароль должен содержать не менее 8 символов.', 'error');
        redirect('index.php?page=register');
    }
    if ($_POST['end_date'] < $_POST['start_date']) {
        flash('Дата окончания не может быть раньше даты начала.', 'error');
        redirect('index.php?page=register');
    }
    try {
        $db->beginTransaction();
        $stmt = $db->prepare("INSERT INTO users (full_name, email, password_hash, role, phone) VALUES (?, ?, ?, 'intern', ?)");
        $stmt->execute([trim($_POST['full_name']), strtolower(trim($_POST['email'])), password_hash($_POST['password'], PASSWORD_DEFAULT), trim($_POST['phone'] ?? '')]);
        $id = (int)$db->lastInsertId();
        $stmt = $db->prepare('INSERT INTO intern_profiles (user_id, university, specialty, course, group_name, practice_topic, start_date, end_date, mentor_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([$id, trim($_POST['university']), trim($_POST['specialty']), (int)$_POST['course'], trim($_POST['group_name'] ?? ''), trim($_POST['practice_topic']), $_POST['start_date'], $_POST['end_date'], (int)$_POST['mentor_id']]);
        $db->commit();
        flash('Регистрация завершена. Теперь войдите в личный кабинет.');
        redirect('index.php?page=login');
    } catch (PDOException $exception) {
        if ($db->inTransaction()) $db->rollBack();
        flash('Пользователь с таким email уже зарегистрирован.', 'error');
        redirect('index.php?page=register');
    }
}

if ($action === 'login') {
    $email = strtolower(trim($_POST['email'] ?? ''));
    $loginRateKey = rate_limit_key('login', $email);
    if (!rate_limit_check($db, $loginRateKey, LOGIN_RATE_LIMIT, LOGIN_RATE_WINDOW)) {
        flash('Слишком много попыток входа. Попробуйте снова через 15 минут.', 'error');
        redirect('index.php?page=login');
    }
    $account = fetch_one($db, 'SELECT * FROM users WHERE email = ?', [$email]);
    if (!$account || !password_verify($_POST['password'] ?? '', $account['password_hash'])) {
        flash('Неверный email или пароль.', 'error');
        redirect('index.php?page=login');
    }
    rate_limit_clear($db, $loginRateKey);
    session_regenerate_id(true);
    rotate_csrf_token();
    unset($account['password_hash']);
    $_SESSION['user'] = $account;
    flash('Добро пожаловать, ' . $account['full_name'] . '!');
    redirect('index.php?page=dashboard');
}

if ($action === 'request_password_reset') {
    $email = strtolower(trim($_POST['email'] ?? ''));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('Введите корректный email.', 'error');
        redirect('index.php?page=forgot');
    }
    if (!rate_limit_check($db, rate_limit_key('reset', $email), RESET_RATE_LIMIT, RESET_RATE_WINDOW)) {
        flash('Слишком много запросов восстановления. Попробуйте позже.', 'error');
        redirect('index.php?page=forgot');
    }

    $db->exec("DELETE FROM password_resets WHERE used_at IS NOT NULL OR expires_at <= datetime('now')");
    $account = fetch_one($db, 'SELECT id, full_name, email FROM users WHERE email = ?', [$email]);
    if ($account) {
        $db->prepare("UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL")->execute([$account['id']]);
        $token = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);
        $expiresAt = gmdate('Y-m-d H:i:s', time() + PASSWORD_RESET_TTL);
        $stmt = $db->prepare('INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)');
        $stmt->execute([$account['id'], $tokenHash, $expiresAt]);
        $resetLink = app_url('index.php?page=reset&token=' . urlencode($token));
        send_password_reset_email($account['email'], $account['full_name'], $resetLink);
    }

    flash('Если аккаунт с таким email существует, ссылка для восстановления отправлена на почту. Проверьте папку «Спам», если письма нет во входящих.');
    redirect('index.php?page=login');
}

if ($action === 'reset_password') {
    $token = trim((string)($_POST['token'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $passwordConfirm = (string)($_POST['password_confirm'] ?? '');
    if (strlen($token) !== 64 || !ctype_xdigit($token)) {
        flash('Ссылка восстановления недействительна. Запросите новую ссылку.', 'error');
        redirect('index.php?page=forgot');
    }
    if (strlen($password) < 8) {
        flash('Пароль должен содержать не менее 8 символов.', 'error');
        redirect('index.php?page=reset&token=' . urlencode($token));
    }
    if ($password !== $passwordConfirm) {
        flash('Пароли не совпадают.', 'error');
        redirect('index.php?page=reset&token=' . urlencode($token));
    }

    $reset = fetch_one(
        $db,
        "SELECT pr.id, pr.user_id FROM password_resets pr JOIN users u ON u.id = pr.user_id WHERE pr.token_hash = ? AND pr.used_at IS NULL AND pr.expires_at > datetime('now')",
        [hash('sha256', $token)]
    );
    if (!$reset) {
        flash('Ссылка восстановления устарела или уже была использована. Запросите новую ссылку.', 'error');
        redirect('index.php?page=forgot');
    }

    $db->beginTransaction();
    try {
        $db->prepare('UPDATE users SET password_hash = ? WHERE id = ?')->execute([password_hash($password, PASSWORD_DEFAULT), $reset['user_id']]);
        $db->prepare('UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE id = ?')->execute([$reset['id']]);
        $db->commit();
    } catch (Throwable $exception) {
        if ($db->inTransaction()) $db->rollBack();
        flash('Не удалось обновить пароль. Попробуйте ещё раз.', 'error');
        redirect('index.php?page=reset&token=' . urlencode($token));
    }

    unset($_SESSION['user']);
    session_regenerate_id(true);
    rotate_csrf_token();
    flash('Пароль обновлён. Теперь войдите в личный кабинет с новым паролем.');
    redirect('index.php?page=login');
}

if ($action === 'logout') {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], (bool)$params['secure'], (bool)$params['httponly']);
    }
    session_destroy();
    redirect();
}

if ($action === 'update_profile') {
    $current = require_role('intern');
    $required = ['full_name', 'email', 'university', 'specialty', 'course', 'practice_topic', 'start_date', 'end_date', 'mentor_id'];
    foreach ($required as $field) {
        if (trim((string)($_POST[$field] ?? '')) === '') {
            flash('Заполните все обязательные поля.', 'error');
            redirect('index.php?page=profile');
        }
    }

    $email = strtolower(trim((string)$_POST['email']));
    $course = (int)$_POST['course'];
    $mentorId = (int)$_POST['mentor_id'];
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $course < 1 || $course > 6) {
        flash('Проверьте email и курс обучения.', 'error');
        redirect('index.php?page=profile');
    }
    if ($_POST['end_date'] < $_POST['start_date']) {
        flash('Дата окончания не может быть раньше даты начала.', 'error');
        redirect('index.php?page=profile');
    }
    if (!fetch_one($db, "SELECT id FROM users WHERE id = ? AND role = 'mentor'", [$mentorId])) {
        flash('Выберите действующего руководителя практики.', 'error');
        redirect('index.php?page=profile');
    }

    try {
        $db->beginTransaction();
        $stmt = $db->prepare('UPDATE users SET full_name = ?, email = ?, phone = ? WHERE id = ?');
        $stmt->execute([trim((string)$_POST['full_name']), $email, trim((string)($_POST['phone'] ?? '')), $current['id']]);
        $stmt = $db->prepare('UPDATE intern_profiles SET university = ?, specialty = ?, course = ?, group_name = ?, practice_topic = ?, start_date = ?, end_date = ?, mentor_id = ? WHERE user_id = ?');
        $stmt->execute([
            trim((string)$_POST['university']),
            trim((string)$_POST['specialty']),
            $course,
            trim((string)($_POST['group_name'] ?? '')),
            trim((string)$_POST['practice_topic']),
            $_POST['start_date'],
            $_POST['end_date'],
            $mentorId,
            $current['id'],
        ]);
        $stmt = $db->prepare("UPDATE tasks SET mentor_id = ? WHERE intern_id = ? AND status <> 'Выполнено'");
        $stmt->execute([$mentorId, $current['id']]);
        $db->commit();
    } catch (PDOException $exception) {
        if ($db->inTransaction()) $db->rollBack();
        flash('Не удалось сохранить данные. Возможно, такой email уже используется.', 'error');
        redirect('index.php?page=profile');
    }

    $account = fetch_one($db, 'SELECT * FROM users WHERE id = ?', [$current['id']]);
    if ($account) {
        unset($account['password_hash']);
        $_SESSION['user'] = $account;
    }
    flash('Данные практики обновлены.');
    redirect('index.php?page=profile');
}

if ($action === 'create_task') {
    $current = require_role('mentor');
    $intern = fetch_one($db, 'SELECT user_id FROM intern_profiles WHERE user_id = ? AND mentor_id = ?', [(int)$_POST['intern_id'], $current['id']]);
    if (!$intern) {
        flash('Практикант не закреплён за вами.', 'error');
    } else {
        $stmt = $db->prepare('INSERT INTO tasks (intern_id, mentor_id, title, description, due_date) VALUES (?, ?, ?, ?, ?)');
        $stmt->execute([(int)$_POST['intern_id'], $current['id'], trim($_POST['title']), trim($_POST['description']), $_POST['due_date']]);
        flash('Задание создано.');
    }
    redirect('index.php?page=tasks');
}

if ($action === 'task_status') {
    $current = require_role('intern');
    $status = (string)($_POST['status'] ?? '');
    if (!in_array($status, ['Новое', 'В работе', 'Выполнено'], true)) {
        flash('Выберите корректный статус задания.', 'error');
        redirect('index.php?page=tasks');
    }
    $task = fetch_one($db, 'SELECT id, status FROM tasks WHERE id = ? AND intern_id = ?', [(int)$_POST['task_id'], $current['id']]);
    if (!$task) {
        flash('Задание не найдено или не закреплено за вами.', 'error');
        redirect('index.php?page=tasks');
    }
    if ($task['status'] === $status) {
        flash('Этот статус уже выбран.');
        redirect('index.php?page=tasks');
    }
    $stmt = $db->prepare('UPDATE tasks SET status = ? WHERE id = ? AND intern_id = ?');
    $stmt->execute([$status, (int)$task['id'], $current['id']]);
    flash('Статус задания обновлён: ' . $status . '.');
    redirect('index.php?page=tasks');
}

if ($action === 'upload_report') {
    $current = require_role('intern');
    $file = $_FILES['report_file'] ?? null;
    $allowed = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip'];
    $extension = strtolower(pathinfo($file['name'] ?? '', PATHINFO_EXTENSION));
    if (!$file || $file['error'] !== UPLOAD_ERR_OK || $file['size'] > MAX_UPLOAD_SIZE || !in_array($extension, $allowed, true)) {
        flash('Допустимы PDF, DOC(X), XLS(X), ZIP размером до 10 МБ.', 'error');
        redirect('index.php?page=reports');
    }
    $title = trim((string)($_POST['title'] ?? ''));
    if ($title === '') {
        flash('Укажите название отчёта.', 'error');
        redirect('index.php?page=reports');
    }
    $taskId = !empty($_POST['task_id']) ? (int)$_POST['task_id'] : null;
    if ($taskId !== null && !fetch_one($db, 'SELECT id FROM tasks WHERE id = ? AND intern_id = ?', [$taskId, $current['id']])) {
        flash('Выбранное задание не найдено или не относится к вашему аккаунту.', 'error');
        redirect('index.php?page=reports');
    }
    $originalName = basename((string)$file['name']);
    $originalName = preg_replace('/[\r\n\\\\\/]+/', '_', $originalName) ?: ('report.' . $extension);
    $storedName = bin2hex(random_bytes(16)) . '.' . $extension;
    if (!move_uploaded_file($file['tmp_name'], UPLOAD_DIR . '/' . $storedName)) {
        flash('Не удалось сохранить файл.', 'error');
        redirect('index.php?page=reports');
    }
    $stmt = $db->prepare('INSERT INTO reports (intern_id, task_id, title, stored_name, original_name) VALUES (?, ?, ?, ?, ?)');
    $stmt->execute([$current['id'], $taskId, $title, $storedName, $originalName]);
    flash('Отчёт загружен и отправлен на проверку.');
    redirect('index.php?page=reports');
}

if ($action === 'review_report') {
    $current = require_role('mentor');
    $status = in_array($_POST['status'] ?? '', ['Принят', 'Требует доработки'], true) ? $_POST['status'] : 'Требует доработки';
    $stmt = $db->prepare('UPDATE reports SET status = ?, mentor_comment = ? WHERE id = ? AND intern_id IN (SELECT user_id FROM intern_profiles WHERE mentor_id = ?)');
    $stmt->execute([$status, trim($_POST['mentor_comment'] ?? ''), (int)$_POST['report_id'], $current['id']]);
    flash('Результат проверки сохранён.');
    redirect('index.php?page=reports');
}

if ($action === 'add_diary') {
    $current = require_role('intern');
    $entryDate = trim($_POST['entry_date'] ?? '');
    $workDone = trim($_POST['work_done'] ?? '');
    $hours = max(1, min(12, (int)($_POST['hours'] ?? 8)));
    if ($entryDate === '' || $workDone === '') {
        flash('Заполните дату и описание выполненной работы.', 'error');
        redirect('index.php?page=diary');
    }
    $stmt = $db->prepare('INSERT INTO diary_entries (intern_id, entry_date, work_done, hours) VALUES (?, ?, ?, ?)');
    $stmt->execute([$current['id'], $entryDate, $workDone, $hours]);
    flash('Запись дневника добавлена и отправлена руководителю.');
    redirect('index.php?page=diary');
}

if ($action === 'review_diary') {
    $current = require_role('mentor');
    $status = in_array($_POST['status'] ?? '', ['Принято', 'Нужна доработка'], true) ? $_POST['status'] : 'Нужна доработка';
    $stmt = $db->prepare('UPDATE diary_entries SET status = ?, mentor_comment = ? WHERE id = ? AND intern_id IN (SELECT user_id FROM intern_profiles WHERE mentor_id = ?)');
    $stmt->execute([$status, trim($_POST['mentor_comment'] ?? ''), (int)$_POST['entry_id'], $current['id']]);
    flash('Комментарий к дневнику сохранён.');
    redirect('index.php?page=diary');
}

if ($action === 'assign_mentor') {
    require_role('admin');
    $internId = (int)($_POST['intern_id'] ?? 0);
    $mentorId = trim((string)($_POST['mentor_id'] ?? '')) === '' ? null : (int)$_POST['mentor_id'];
    $intern = fetch_one($db, "SELECT u.id, u.full_name FROM users u JOIN intern_profiles p ON p.user_id = u.id WHERE u.id = ? AND u.role = 'intern'", [$internId]);
    $mentor = $mentorId ? fetch_one($db, "SELECT id, full_name FROM users WHERE id = ? AND role = 'mentor'", [$mentorId]) : null;
    if (!$intern) {
        flash('Практикант не найден.', 'error');
        redirect('index.php?page=assignments');
    }
    if ($mentorId && !$mentor) {
        flash('Выбранный руководитель не найден.', 'error');
        redirect('index.php?page=assignments');
    }
    $stmt = $db->prepare('UPDATE intern_profiles SET mentor_id = ? WHERE user_id = ?');
    $stmt->execute([$mentorId, $internId]);
    if ($mentorId && !empty($_POST['transfer_tasks'])) {
        $stmt = $db->prepare("UPDATE tasks SET mentor_id = ? WHERE intern_id = ? AND status <> 'Выполнено'");
        $stmt->execute([$mentorId, $internId]);
    }
    flash($mentor ? 'Практикант ' . $intern['full_name'] . ' закреплён за руководителем ' . $mentor['full_name'] . '.' : 'Практикант снят с назначения.');
    redirect('index.php?page=assignments');
}

if ($action === 'assign_bulk') {
    require_role('admin');
    $mentorId = (int)($_POST['mentor_id'] ?? 0);
    $internIds = array_values(array_unique(array_filter(array_map('intval', $_POST['intern_ids'] ?? []))));
    $mentor = fetch_one($db, "SELECT id, full_name FROM users WHERE id = ? AND role = 'mentor'", [$mentorId]);
    if (!$mentor) {
        flash('Выберите действующего руководителя для массового назначения.', 'error');
        redirect('index.php?page=assignments');
    }
    if (!$internIds) {
        flash('Отметьте хотя бы одного практиканта.', 'error');
        redirect('index.php?page=assignments');
    }
    $updated = 0;
    $assign = $db->prepare("UPDATE intern_profiles SET mentor_id = ? WHERE user_id = ? AND user_id IN (SELECT id FROM users WHERE role = 'intern')");
    $transfer = $db->prepare("UPDATE tasks SET mentor_id = ? WHERE intern_id = ? AND status <> 'Выполнено'");
    foreach ($internIds as $internId) {
        $assign->execute([$mentorId, $internId]);
        if ($assign->rowCount() > 0) {
            $updated++;
            if (!empty($_POST['transfer_tasks'])) {
                $transfer->execute([$mentorId, $internId]);
            }
        }
    }
    flash('Массовое назначение выполнено. Обновлено практикантов: ' . $updated . '.');
    redirect('index.php?page=assignments');
}

if ($action === 'finalize') {
    $current = require_role('mentor');
    $stmt = $db->prepare("UPDATE intern_profiles SET final_grade = ?, conclusion = ?, status = 'Практика завершена' WHERE user_id = ? AND mentor_id = ?");
    $stmt->execute([trim($_POST['final_grade']), trim($_POST['conclusion']), (int)$_POST['intern_id'], $current['id']]);
    flash('Итоговое заключение сохранено.');
    redirect('index.php?page=interns');
}

if ($action === 'download') {
    $current = require_role('intern', 'mentor', 'admin');
    $report = fetch_one($db, 'SELECT * FROM reports WHERE id = ?', [(int)($_GET['id'] ?? 0)]);
    $allowed = $report && (
        $current['role'] === 'admin' ||
        ($current['role'] === 'intern' && (int)$report['intern_id'] === (int)$current['id']) ||
        ($current['role'] === 'mentor' && fetch_one($db, 'SELECT user_id FROM intern_profiles WHERE user_id = ? AND mentor_id = ?', [$report['intern_id'], $current['id']]))
    );
    $uploadRoot = realpath(UPLOAD_DIR);
    $filePath = $report ? realpath(UPLOAD_DIR . '/' . $report['stored_name']) : false;
    if (!$allowed || !$uploadRoot || !$filePath || strncmp($filePath, $uploadRoot . DIRECTORY_SEPARATOR, strlen($uploadRoot . DIRECTORY_SEPARATOR)) !== 0 || !is_file($filePath)) {
        http_response_code(404);
        exit('Файл не найден');
    }
    $downloadName = basename((string)$report['original_name']);
    $downloadName = preg_replace('/[\r\n\\\\\/]+/', '_', $downloadName) ?: 'report';
    $encodedName = rawurlencode($downloadName);
    header('Content-Type: application/octet-stream');
    header('X-Content-Type-Options: nosniff');
    header('Content-Length: ' . filesize($filePath));
    header('Content-Disposition: attachment; filename="' . addcslashes($downloadName, "\"\\") . '"; filename*=UTF-8\'\'' . $encodedName);
    readfile($filePath);
    exit;
}

$page = $_GET['page'] ?? (user() ? 'dashboard' : 'home');
$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
$mentors = fetch_all($db, "SELECT id, full_name, department, position FROM users WHERE role = 'mentor' ORDER BY full_name");
$publicPages = ['home', 'about', 'login', 'register', 'forgot', 'reset'];
$current = user();
if (!in_array($page, $publicPages, true)) {
    $current = require_role('intern', 'mentor', 'admin');
}
if ($page === 'intern_detail' && $current && $current['role'] !== 'mentor') {
    flash('Карточка практиканта доступна только руководителю.', 'error');
    redirect('index.php?page=dashboard');
}

function nav_items(?array $current): array
{
    if (!$current) return ['home' => 'Главная', 'about' => 'О практике', 'login' => 'Вход'];
    if ($current['role'] === 'intern') return ['dashboard' => 'Обзор', 'tasks' => 'Задания', 'diary' => 'Дневник', 'reports' => 'Отчёты', 'profile' => 'Моя практика'];
    if ($current['role'] === 'mentor') return ['dashboard' => 'Обзор', 'interns' => 'Практиканты', 'tasks' => 'Задания', 'diary' => 'Дневники', 'reports' => 'Отчёты'];
    return ['dashboard' => 'Обзор', 'users' => 'Пользователи', 'assignments' => 'Назначения'];
}

$pageTitle = '';
if ($current) {
    $pageTitle = $page === 'dashboard'
        ? greeting_text() . ', ' . short_name((string)$current['full_name'])
        : (nav_items($current)[$page] ?? ($page === 'intern_detail' ? 'Карточка практиканта' : 'Личный кабинет'));
}
?>
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <meta name="theme-color" content="#f5f8fd" media="(prefers-color-scheme: light)">
    <meta name="theme-color" content="#061022" media="(prefers-color-scheme: dark)">
    <title><?= e(APP_NAME) ?></title>
    <script>
        (() => {
            const theme = localStorage.getItem('practice_theme') || 'light';
            document.documentElement.dataset.theme = theme === 'dark' ? 'dark' : 'light';
        })();
    </script>
    <link rel="stylesheet" href="assets/style.css?v=20260606-mobile-theme">
    <link rel="stylesheet" href="assets/responsive-theme.css?v=20260608-intern-detail">
</head>
<body>
<header class="topbar">
    <div class="topbar-shell">
        <a class="brand" href="index.php"><img src="assets/mincifra-logo.png" alt="Минцифра Оренбургской области"><span><b>Практика.Цифра</b></span></a>
        <div class="topbar-right">
            <div class="theme-switch" role="group" aria-label="Выбор темы сайта">
                <button class="theme-option" type="button" data-theme-value="light">Обычная</button>
                <button class="theme-option" type="button" data-theme-value="dark">Тёмная</button>
            </div>
            <button class="menu-toggle" type="button" aria-label="Меню">☰</button>
            <nav>
                <?php foreach (nav_items(user()) as $key => $label): ?>
                    <a class="<?= $page === $key ? 'active' : '' ?>" href="index.php?page=<?= e($key) ?>"><?= e($label) ?></a>
                <?php endforeach; ?>
                <?php if (user()): ?><form class="logout-form" method="post"><input type="hidden" name="action" value="logout"><?= csrf_field() ?><button class="logout" type="submit">Выйти</button></form><?php else: ?><a class="button small" href="index.php?page=register">Подать заявку</a><?php endif; ?>
            </nav>
        </div>
    </div>
</header>
<main>
<?php if ($flash): ?><div class="flash <?= e($flash['type']) ?>"><?= e($flash['message']) ?></div><?php endif; ?>

<?php if ($page === 'home'): ?>
    <section class="hero">
        <div>
            <span class="eyebrow">Единая цифровая среда практики</span>
            <h1>От заявки до итогового заключения — в одной системе</h1>
            <p>Организация, сопровождение и контроль прохождения практики студентами в Министерстве цифрового развития и связи Оренбургской области.</p>
            <div class="actions"><a class="button" href="index.php?page=register">Подать заявку</a><a class="button secondary" href="index.php?page=about">Как это работает</a></div>
        </div>
        <div class="hero-visual">
            <div class="hero-glow"></div>
            <img class="hero-brand-card" src="assets/mincifra-card.jpg" alt="Министерство цифрового развития и связи Оренбургской области">
            <div class="hero-card">
                <img src="assets/orenburg-emblem.webp" alt="Герб Оренбургской области"><div><b>Официальная система</b></div>
            </div>
        </div>
    </section>
    <section class="section"><div class="section-head"><span class="eyebrow">Возможности</span><h2>Практика без лишней переписки</h2></div>
        <div class="feature-showcase">
            <article class="feature feature-primary"><b>01</b><h3>Практикантам</h3><p>Регистрация, выбор руководителя, задания, дневник практики и загрузка отчётов в одном кабинете.</p></article>
            <article class="feature feature-primary"><b>02</b><h3>Руководителям</h3><p>Общий прогресс студентов, постановка задач, проверка отчётов и ежедневных записей дневника.</p></article>
        </div>
    </section>
    <section class="section location-section">
        <div class="location-card">
            <div class="location-copy">
                <span class="eyebrow">Где мы находимся</span>
                <h2>Здание Министерства цифрового развития и связи</h2>
                <a class="button secondary" href="https://yandex.ru/maps/-/CPX0MI7h" target="_blank" rel="noopener">Открыть в Яндекс.Картах</a>
            </div>
            <div class="map-frame">
                <iframe src="https://yandex.ru/map-widget/v1/?ll=55.096744%2C51.761768&amp;pt=55.096409%2C51.761616%2Cpm2rdm&amp;z=18" title="Карта расположения здания Министерства цифрового развития и связи" width="100%" height="720" loading="lazy" allowfullscreen></iframe>
            </div>
        </div>
    </section>
<?php elseif ($page === 'about'): ?>
    <section class="page-head"><span class="eyebrow">О программе</span><h1>Как пройти практику</h1><p>Четыре понятных этапа от регистрации до получения заключения.</p></section>
    <div class="steps"><?php foreach ([['01','Создайте аккаунт','Укажите учебное заведение, сроки и тему практики.'],['02','Выберите руководителя','Закрепитесь за специалистом подходящего отдела.'],['03','Выполняйте задания','Следите за сроками и загружайте отчёты.'],['04','Получите заключение','Руководитель оценит результаты практики.']] as $step): ?><article><b><?= $step[0] ?></b><h3><?= $step[1] ?></h3><p><?= $step[2] ?></p></article><?php endforeach; ?></div>
<?php elseif ($page === 'login'): ?>
    <section class="auth-wrap"><form class="panel auth-card" method="post"><input type="hidden" name="action" value="login"><?= csrf_field() ?><span class="eyebrow">Личный кабинет</span><h1>Вход в систему</h1><label>Email<input type="email" name="email" required placeholder="name@example.ru"></label><label>Пароль<input type="password" name="password" required placeholder="Не менее 8 символов"></label><button class="button" type="submit">Войти</button><div class="auth-links"><a href="index.php?page=forgot">Забыли пароль?</a><span>Нет аккаунта? <a href="index.php?page=register">Зарегистрироваться</a></span></div></form></section>
<?php elseif ($page === 'forgot'): ?>
    <section class="auth-wrap"><form class="panel auth-card" method="post"><input type="hidden" name="action" value="request_password_reset"><?= csrf_field() ?><span class="eyebrow">Восстановление доступа</span><h1>Забыли пароль?</h1><p class="muted">Укажите email аккаунта. Мы отправим ссылку для создания нового пароля, если такой пользователь есть в системе.</p><label>Email<input type="email" name="email" required placeholder="name@example.ru"></label><button class="button" type="submit">Отправить ссылку</button><div class="auth-links single"><a href="index.php?page=login">Вернуться ко входу</a></div></form></section>
<?php elseif ($page === 'reset'): ?>
    <?php
        $resetToken = trim((string)($_GET['token'] ?? ''));
        $resetIsValid = strlen($resetToken) === 64 && ctype_xdigit($resetToken) && fetch_one($db, "SELECT id FROM password_resets WHERE token_hash = ? AND used_at IS NULL AND expires_at > datetime('now')", [hash('sha256', $resetToken)]);
    ?>
    <section class="auth-wrap">
        <?php if ($resetIsValid): ?>
            <form class="panel auth-card" method="post"><input type="hidden" name="action" value="reset_password"><?= csrf_field() ?><input type="hidden" name="token" value="<?= e($resetToken) ?>"><span class="eyebrow">Новый пароль</span><h1>Создайте пароль</h1><p class="muted">Введите новый пароль для входа в личный кабинет. Ссылка восстановления действует один час.</p><label>Новый пароль<input type="password" name="password" minlength="8" required placeholder="Не менее 8 символов"></label><label>Повторите пароль<input type="password" name="password_confirm" minlength="8" required placeholder="Повторите новый пароль"></label><button class="button" type="submit">Сохранить пароль</button><div class="auth-links single"><a href="index.php?page=login">Вернуться ко входу</a></div></form>
        <?php else: ?>
            <section class="panel auth-card"><span class="eyebrow">Ссылка недействительна</span><h1>Нужна новая ссылка</h1><p class="muted">Ссылка восстановления устарела, уже была использована или указана неверно. Запросите новую ссылку на почту.</p><a class="button" href="index.php?page=forgot">Запросить восстановление</a><div class="auth-links single"><a href="index.php?page=login">Вернуться ко входу</a></div></section>
        <?php endif; ?>
    </section>
<?php elseif ($page === 'register'): ?>
    <section class="page-head compact"><span class="eyebrow">Новая заявка</span><h1>Регистрация практиканта</h1><p>Заполните данные практики и сразу выберите руководителя.</p></section>
    <form class="panel form-grid" method="post"><input type="hidden" name="action" value="register"><?= csrf_field() ?>
        <h3 class="full">Личные данные</h3><label>ФИО *<input name="full_name" required></label><label>Email *<input type="email" name="email" required></label><label>Телефон<input name="phone"></label><label>Пароль *<input type="password" name="password" minlength="8" required></label>
        <h3 class="full">Обучение и практика</h3><label>Учебное заведение *<input name="university" required></label><label>Направление подготовки *<input name="specialty" required></label><label>Курс *<input type="number" min="1" max="6" name="course" required></label><label>Группа<input name="group_name"></label><label class="full">Тема практики *<input name="practice_topic" required></label><label>Дата начала *<input type="date" name="start_date" required></label><label>Дата окончания *<input type="date" name="end_date" required></label><label class="full">Руководитель *<select name="mentor_id" required><option value="">Выберите руководителя</option><?php foreach ($mentors as $mentor): ?><option value="<?= $mentor['id'] ?>"><?= e($mentor['full_name'] . ' — ' . $mentor['department']) ?></option><?php endforeach; ?></select></label><button class="button full" type="submit">Создать аккаунт</button>
    </form>
<?php else: ?>
    <section class="dashboard-head"><div><span class="eyebrow"><?= e(role_name($current['role'])) ?></span><h1><?= e($pageTitle) ?></h1></div><div class="user-chip"><span><img src="assets/mincifra-symbol.jpg" alt=""></span><div><b><?= e($current['full_name']) ?></b></div></div></section>

    <?php if ($page === 'dashboard' && $current['role'] === 'intern'):
        $profile = fetch_one($db, 'SELECT p.*, u.full_name mentor_name, u.department FROM intern_profiles p LEFT JOIN users u ON u.id = p.mentor_id WHERE p.user_id = ?', [$current['id']]);
        $stats = fetch_one($db, "SELECT COUNT(*) total, SUM(CASE WHEN status='Выполнено' THEN 1 ELSE 0 END) done FROM tasks WHERE intern_id=?", [$current['id']]); ?>
        <div class="stat-grid"><article class="stat"><span>Общий прогресс</span><strong><?= progress($db, $current['id']) ?>%</strong><div class="progress"><i style="width:<?= progress($db, $current['id']) ?>%"></i></div></article><article class="stat"><span>Заданий выполнено</span><strong><?= (int)$stats['done'] ?> / <?= (int)$stats['total'] ?></strong></article><article class="stat"><span>Статус практики</span><strong class="status-text"><?= e($profile['status']) ?></strong></article></div>
        <div class="two-col"><section class="panel"><h2>Моя практика</h2><dl class="details"><dt>Тема</dt><dd><?= e($profile['practice_topic']) ?></dd><dt>Период</dt><dd><?= e($profile['start_date']) ?> — <?= e($profile['end_date']) ?></dd><dt>Руководитель</dt><dd><?= e($profile['mentor_name']) ?><small><?= e($profile['department']) ?></small></dd></dl></section><section class="panel"><h2>Быстрые действия</h2><div class="quick"><a href="index.php?page=tasks">Открыть задания <b>→</b></a><a href="index.php?page=diary">Заполнить дневник <b>→</b></a><a href="index.php?page=reports">Загрузить отчёт <b>→</b></a><a href="index.php?page=profile">Посмотреть заключение <b>→</b></a></div></section></div>
    <?php elseif ($page === 'dashboard' && $current['role'] === 'mentor'):
        $interns = fetch_all($db, 'SELECT u.id, u.full_name, p.* FROM users u JOIN intern_profiles p ON p.user_id=u.id WHERE p.mentor_id=? ORDER BY u.full_name', [$current['id']]);
        $pending = (int)fetch_one($db, "SELECT COUNT(*) amount FROM reports r JOIN intern_profiles p ON p.user_id=r.intern_id WHERE p.mentor_id=? AND r.status='На проверке'", [$current['id']])['amount'];
        $pendingDiary = (int)fetch_one($db, "SELECT COUNT(*) amount FROM diary_entries d JOIN intern_profiles p ON p.user_id=d.intern_id WHERE p.mentor_id=? AND d.status='На проверке'", [$current['id']])['amount']; ?>
        <div class="stat-grid"><article class="stat"><span>Практикантов</span><strong><?= count($interns) ?></strong></article><article class="stat"><span>Отчётов на проверке</span><strong><?= $pending ?></strong></article><article class="stat"><span>Записей дневника</span><strong><?= $pendingDiary ?></strong></article><article class="stat"><span>Средний прогресс</span><strong><?= count($interns) ? round(array_sum(array_map(fn($i) => progress($db, (int)$i['id']), $interns)) / count($interns)) : 0 ?>%</strong></article></div>
        <section class="panel"><div class="panel-head"><h2>Прогресс практикантов</h2><a href="index.php?page=interns">Все практиканты →</a></div><?php render_intern_table($db, $interns); ?></section>
    <?php elseif ($page === 'dashboard' && $current['role'] === 'admin'):
        $counts = []; foreach (['intern','mentor','admin'] as $r) $counts[$r]=(int)fetch_one($db,'SELECT COUNT(*) c FROM users WHERE role=?',[$r])['c']; ?>
        <div class="stat-grid"><article class="stat"><span>Практикантов</span><strong><?= $counts['intern'] ?></strong></article><article class="stat"><span>Руководителей</span><strong><?= $counts['mentor'] ?></strong></article><article class="stat"><span>Всего пользователей</span><strong><?= array_sum($counts) ?></strong></article></div><section class="panel"><h2>Управление системой</h2><div class="quick"><a href="index.php?page=users">Список пользователей <b>→</b></a><a href="index.php?page=assignments">Изменить назначения <b>→</b></a></div></section>
    <?php elseif ($page === 'tasks'):
        if ($current['role'] === 'intern') $tasks=fetch_all($db,'SELECT t.*, u.full_name mentor_name FROM tasks t JOIN users u ON u.id=t.mentor_id WHERE intern_id=? ORDER BY due_date',[$current['id']]);
        else { $tasks=fetch_all($db,'SELECT t.*, u.full_name intern_name FROM tasks t JOIN users u ON u.id=t.intern_id JOIN intern_profiles p ON p.user_id=t.intern_id WHERE p.mentor_id=? ORDER BY due_date',[$current['id']]); $interns=fetch_all($db,'SELECT u.id,u.full_name FROM users u JOIN intern_profiles p ON p.user_id=u.id WHERE p.mentor_id=?',[$current['id']]); } ?>
        <?php if ($current['role']==='mentor'): ?><details class="panel create-box"><summary>Создать новое задание</summary><form class="form-grid" method="post"><input type="hidden" name="action" value="create_task"><?= csrf_field() ?><label>Практикант<select name="intern_id" required><?php foreach($interns as $i):?><option value="<?=$i['id']?>"><?=e($i['full_name'])?></option><?php endforeach;?></select></label><label>Срок выполнения<input type="date" name="due_date" required></label><label class="full">Название<input name="title" required></label><label class="full">Описание<textarea name="description" required></textarea></label><button class="button full">Создать задание</button></form></details><?php endif; ?>
        <div class="card-list"><?php foreach($tasks as $task):?><article class="task-card"><div><span class="badge"><?=e($task['status'])?></span><h3><?=e($task['title'])?></h3><p><?=e($task['description'])?></p><small><?= $current['role']==='intern'?'Руководитель: '.e($task['mentor_name']):'Практикант: '.e($task['intern_name']) ?> · до <?=e($task['due_date'])?></small></div><?php if($current['role']==='intern'):?><form method="post"><input type="hidden" name="action" value="task_status"><?= csrf_field() ?><input type="hidden" name="task_id" value="<?=$task['id']?>"><select name="status"><?php foreach(['Новое','В работе','Выполнено'] as $statusOption):?><option value="<?=e($statusOption)?>" <?=$task['status']===$statusOption?'selected':''?>><?=e($statusOption)?></option><?php endforeach;?></select><button class="button small">Обновить</button></form><?php endif;?></article><?php endforeach;?><?php if(!$tasks):?><div class="empty">Заданий пока нет.</div><?php endif;?></div>
    <?php elseif ($page === 'reports'):
        if($current['role']==='intern'){ $reports=fetch_all($db,'SELECT r.*,t.title task_title FROM reports r LEFT JOIN tasks t ON t.id=r.task_id WHERE r.intern_id=? ORDER BY r.uploaded_at DESC',[$current['id']]); $tasks=fetch_all($db,'SELECT id,title FROM tasks WHERE intern_id=?',[$current['id']]); }
        else { $reports=fetch_all($db,'SELECT r.*,u.full_name intern_name,t.title task_title FROM reports r JOIN users u ON u.id=r.intern_id LEFT JOIN tasks t ON t.id=r.task_id JOIN intern_profiles p ON p.user_id=r.intern_id WHERE p.mentor_id=? ORDER BY r.uploaded_at DESC',[$current['id']]); } ?>
        <?php if($current['role']==='intern'):?><form class="panel form-grid" method="post" enctype="multipart/form-data"><input type="hidden" name="action" value="upload_report"><?= csrf_field() ?><h2 class="full">Загрузить отчёт</h2><label>Название<input name="title" required></label><label>Связанное задание<select name="task_id"><option value="">Без задания</option><?php foreach($tasks as $t):?><option value="<?=$t['id']?>"><?=e($t['title'])?></option><?php endforeach;?></select></label><label class="full file-field">Файл до 10 МБ<input type="file" name="report_file" required accept=".pdf,.doc,.docx,.xls,.xlsx,.zip"></label><button class="button full">Отправить на проверку</button></form><?php endif;?>
        <div class="card-list"><?php foreach($reports as $r):?><article class="report-card"><div><span class="badge"><?=e($r['status'])?></span><h3><?=e($r['title'])?></h3><p><?=e($r['task_title'] ?: 'Общий отчёт')?><?php if(isset($r['intern_name'])):?> · <?=e($r['intern_name'])?><?php endif;?></p><a href="index.php?action=download&id=<?=$r['id']?>">Скачать <?=e($r['original_name'])?></a><?php if($r['mentor_comment']):?><blockquote><?=e($r['mentor_comment'])?></blockquote><?php endif;?></div><?php if($current['role']==='mentor'):?><form method="post" class="review"><input type="hidden" name="action" value="review_report"><?= csrf_field() ?><input type="hidden" name="report_id" value="<?=$r['id']?>"><select name="status"><option>Принят</option><option>Требует доработки</option></select><input name="mentor_comment" placeholder="Комментарий"><button class="button small">Сохранить</button></form><?php endif;?></article><?php endforeach;?><?php if(!$reports):?><div class="empty">Отчётов пока нет.</div><?php endif;?></div>
    <?php elseif ($page === 'diary'):
        if ($current['role'] === 'intern') {
            $entries = fetch_all($db, 'SELECT * FROM diary_entries WHERE intern_id = ? ORDER BY entry_date DESC, created_at DESC', [$current['id']]);
        } else {
            $entries = fetch_all($db, 'SELECT d.*, u.full_name intern_name FROM diary_entries d JOIN users u ON u.id = d.intern_id JOIN intern_profiles p ON p.user_id = d.intern_id WHERE p.mentor_id = ? ORDER BY d.entry_date DESC, d.created_at DESC', [$current['id']]);
        } ?>
        <?php if($current['role']==='intern'):?><form class="panel form-grid diary-form" method="post"><input type="hidden" name="action" value="add_diary"><?= csrf_field() ?><h2 class="full">Новая запись дневника</h2><label>Дата работы<input type="date" name="entry_date" value="<?=date('Y-m-d')?>" required></label><label>Часов практики<input type="number" name="hours" min="1" max="12" value="8" required></label><label class="full">Что было сделано<textarea name="work_done" placeholder="Опишите выполненные задачи, изученные материалы и результат дня" required></textarea></label><button class="button full">Сохранить запись</button></form><?php endif; ?>
        <div class="diary-list"><?php foreach($entries as $entry):?><article class="diary-card"><div class="diary-date"><strong><?=e($entry['entry_date'])?></strong><span><?= (int)$entry['hours'] ?> ч</span></div><div class="diary-body"><span class="badge"><?=e($entry['status'])?></span><h3><?= $current['role']==='mentor' ? e($entry['intern_name']) : 'Запись дневника' ?></h3><p><?=nl2br(e($entry['work_done']))?></p><?php if($entry['mentor_comment']):?><blockquote><?=e($entry['mentor_comment'])?></blockquote><?php endif;?></div><?php if($current['role']==='mentor'):?><form method="post" class="review diary-review"><input type="hidden" name="action" value="review_diary"><?= csrf_field() ?><input type="hidden" name="entry_id" value="<?=$entry['id']?>"><select name="status"><option>Принято</option><option>Нужна доработка</option></select><input name="mentor_comment" placeholder="Комментарий руководителя"><button class="button small">Проверить</button></form><?php endif;?></article><?php endforeach;?><?php if(!$entries):?><div class="empty">Записей дневника пока нет.</div><?php endif;?></div>
    <?php elseif ($page === 'interns' && $current['role']==='mentor'):
        $interns=fetch_all($db,'SELECT u.id,u.full_name,u.email,p.* FROM users u JOIN intern_profiles p ON p.user_id=u.id WHERE p.mentor_id=? ORDER BY u.full_name',[$current['id']]); ?>
        <section class="panel"><?php render_intern_table($db,$interns,true);?></section>
    <?php elseif ($page === 'intern_detail' && $current['role']==='mentor'):
        $internId = (int)($_GET['id'] ?? 0);
        $intern = fetch_one($db, 'SELECT u.id,u.full_name,u.email,u.phone,p.*,m.full_name mentor_name,m.email mentor_email FROM users u JOIN intern_profiles p ON p.user_id=u.id LEFT JOIN users m ON m.id=p.mentor_id WHERE u.id=? AND u.role=\'intern\' AND p.mentor_id=?', [$internId, $current['id']]);
        if (!$intern): ?>
            <section class="panel"><div class="empty">Практикант не найден или не закреплён за вами.</div><a class="button secondary" href="index.php?page=interns">Вернуться к списку</a></section>
        <?php else:
            $taskStats = fetch_one($db, "SELECT COUNT(*) total, SUM(CASE WHEN status='Выполнено' THEN 1 ELSE 0 END) done FROM tasks WHERE intern_id=?", [$internId]);
            $reportStats = fetch_one($db, "SELECT COUNT(*) total, SUM(CASE WHEN status='На проверке' THEN 1 ELSE 0 END) pending FROM reports WHERE intern_id=?", [$internId]);
            $diaryStats = fetch_one($db, "SELECT COUNT(*) total, SUM(hours) hours FROM diary_entries WHERE intern_id=?", [$internId]);
            $internTasks = fetch_all($db, 'SELECT * FROM tasks WHERE intern_id=? ORDER BY due_date, created_at DESC', [$internId]);
            $internReports = fetch_all($db, 'SELECT r.*,t.title task_title FROM reports r LEFT JOIN tasks t ON t.id=r.task_id WHERE r.intern_id=? ORDER BY r.uploaded_at DESC', [$internId]);
            $internDiary = fetch_all($db, 'SELECT * FROM diary_entries WHERE intern_id=? ORDER BY entry_date DESC, created_at DESC', [$internId]);
            $internProgress = progress($db, $internId);
        ?>
        <section class="panel intern-detail-hero">
            <div>
                <a class="button secondary small" href="index.php?page=interns">← К списку практикантов</a>
                <span class="badge"><?=e($intern['status'])?></span>
                <h2><?=e($intern['full_name'])?></h2>
                <p><?=e($intern['practice_topic'])?></p>
            </div>
            <div class="intern-progress-ring"><strong><?=$internProgress?>%</strong><span>общий прогресс</span></div>
        </section>
        <div class="stat-grid">
            <article class="stat"><span>Заданий выполнено</span><strong><?= (int)($taskStats['done'] ?? 0) ?> / <?= (int)($taskStats['total'] ?? 0) ?></strong></article>
            <article class="stat"><span>Отчётов всего</span><strong><?= (int)($reportStats['total'] ?? 0) ?></strong></article>
            <article class="stat"><span>Отчётов на проверке</span><strong><?= (int)($reportStats['pending'] ?? 0) ?></strong></article>
            <article class="stat"><span>Часов в дневнике</span><strong><?= (int)($diaryStats['hours'] ?? 0) ?></strong></article>
        </div>
        <div class="two-col intern-detail-grid">
            <section class="panel"><h2>Данные практики</h2><dl class="details"><dt>Учебное заведение</dt><dd><?=e($intern['university'])?></dd><dt>Направление</dt><dd><?=e($intern['specialty'])?></dd><dt>Курс и группа</dt><dd><?=e((string)$intern['course'])?> курс<?= $intern['group_name'] ? ', '.e($intern['group_name']) : '' ?></dd><dt>Период</dt><dd><?=e($intern['start_date'])?> — <?=e($intern['end_date'])?></dd></dl></section>
            <section class="panel"><h2>Контакты</h2><dl class="details"><dt>Email</dt><dd><?=e($intern['email'])?></dd><dt>Телефон</dt><dd><?=e($intern['phone'] ?: 'Не указан')?></dd><dt>Руководитель</dt><dd><?=e($intern['mentor_name'])?><small><?=e($intern['mentor_email'])?></small></dd><dt>Статус</dt><dd><?=e($intern['status'])?></dd></dl></section>
        </div>
        <section class="panel"><div class="panel-head"><h2>Задания практиканта</h2><a href="index.php?page=tasks">Все задания →</a></div><div class="card-list"><?php foreach($internTasks as $task):?><article class="task-card"><div><span class="badge"><?=e($task['status'])?></span><h3><?=e($task['title'])?></h3><p><?=e($task['description'])?></p><small>Срок выполнения: <?=e($task['due_date'])?></small></div></article><?php endforeach;?><?php if(!$internTasks):?><div class="empty">Заданий у практиканта пока нет.</div><?php endif;?></div></section>
        <section class="panel"><div class="panel-head"><h2>Отчёты</h2><a href="index.php?page=reports">Все отчёты →</a></div><div class="card-list"><?php foreach($internReports as $r):?><article class="report-card"><div><span class="badge"><?=e($r['status'])?></span><h3><?=e($r['title'])?></h3><p><?=e($r['task_title'] ?: 'Общий отчёт')?> · загружен <?=e(substr($r['uploaded_at'],0,10))?></p><a href="index.php?action=download&id=<?=$r['id']?>">Скачать <?=e($r['original_name'])?></a><?php if($r['mentor_comment']):?><blockquote><?=e($r['mentor_comment'])?></blockquote><?php endif;?></div></article><?php endforeach;?><?php if(!$internReports):?><div class="empty">Отчётов у практиканта пока нет.</div><?php endif;?></div></section>
        <section class="panel"><div class="panel-head"><h2>Дневник практики</h2><a href="index.php?page=diary">Все дневники →</a></div><div class="diary-list"><?php foreach($internDiary as $entry):?><article class="diary-card"><div class="diary-date"><strong><?=e($entry['entry_date'])?></strong><span><?= (int)$entry['hours'] ?> ч</span></div><div class="diary-body"><span class="badge"><?=e($entry['status'])?></span><h3>Запись дневника</h3><p><?=nl2br(e($entry['work_done']))?></p><?php if($entry['mentor_comment']):?><blockquote><?=e($entry['mentor_comment'])?></blockquote><?php endif;?></div></article><?php endforeach;?><?php if(!$internDiary):?><div class="empty">Записей дневника у практиканта пока нет.</div><?php endif;?></div></section>
        <?php endif; ?>
    <?php elseif ($page === 'profile' && $current['role']==='intern'):
        $p=fetch_one($db,'SELECT p.*,self.full_name,self.email,self.phone,mentor.full_name mentor_name,mentor.email mentor_email FROM intern_profiles p JOIN users self ON self.id=p.user_id LEFT JOIN users mentor ON mentor.id=p.mentor_id WHERE p.user_id=?',[$current['id']]);?>
        <div class="two-col"><section class="panel"><h2>Данные практики</h2><dl class="details"><dt>Тема</dt><dd><?=e($p['practice_topic'])?></dd><dt>Учебное заведение</dt><dd><?=e($p['university'])?></dd><dt>Направление</dt><dd><?=e($p['specialty'])?></dd><dt>Период</dt><dd><?=e($p['start_date'])?> — <?=e($p['end_date'])?></dd><dt>Руководитель</dt><dd><?=e($p['mentor_name'])?><small><?=e($p['mentor_email'])?></small></dd></dl></section><section class="panel"><h2>Итоговое заключение</h2><?php if($p['conclusion']):?><div class="grade"><?=e($p['final_grade'])?></div><p><?=e($p['conclusion'])?></p><?php else:?><div class="empty">Заключение появится после завершения практики.</div><?php endif;?></section></div>
        <form class="panel form-grid profile-edit" method="post"><input type="hidden" name="action" value="update_profile"><?= csrf_field() ?>
            <h2 class="full">Изменить регистрационные данные</h2>
            <h3 class="full">Личные данные</h3>
            <label>ФИО *<input name="full_name" value="<?=e($p['full_name'])?>" required></label>
            <label>Email *<input type="email" name="email" value="<?=e($p['email'])?>" required></label>
            <label>Телефон<input name="phone" value="<?=e($p['phone'])?>"></label>
            <h3 class="full">Обучение и практика</h3>
            <label>Учебное заведение *<input name="university" value="<?=e($p['university'])?>" required></label>
            <label>Направление подготовки *<input name="specialty" value="<?=e($p['specialty'])?>" required></label>
            <label>Курс *<input type="number" min="1" max="6" name="course" value="<?=e((string)$p['course'])?>" required></label>
            <label>Группа<input name="group_name" value="<?=e($p['group_name'])?>"></label>
            <label class="full">Тема практики *<input name="practice_topic" value="<?=e($p['practice_topic'])?>" required></label>
            <label>Дата начала *<input type="date" name="start_date" value="<?=e($p['start_date'])?>" required></label>
            <label>Дата окончания *<input type="date" name="end_date" value="<?=e($p['end_date'])?>" required></label>
            <label class="full">Руководитель *<select name="mentor_id" required><option value="">Выберите руководителя</option><?php foreach ($mentors as $mentor): ?><option value="<?= $mentor['id'] ?>" <?= (int)$p['mentor_id'] === (int)$mentor['id'] ? 'selected' : '' ?>><?= e($mentor['full_name'] . ' — ' . $mentor['department']) ?></option><?php endforeach; ?></select></label>
            <button class="button full" type="submit">Сохранить изменения</button>
        </form>
    <?php elseif ($page === 'users' && $current['role']==='admin'):
        $users=fetch_all($db,'SELECT * FROM users ORDER BY created_at DESC');?><section class="panel table-wrap"><table><thead><tr><th>Пользователь</th><th>Роль</th><th>Email</th><th>Дата регистрации</th></tr></thead><tbody><?php foreach($users as $u):?><tr><td><b><?=e($u['full_name'])?></b></td><td><span class="badge"><?=e(role_name($u['role']))?></span></td><td><?=e($u['email'])?></td><td><?=e(substr($u['created_at'],0,10))?></td></tr><?php endforeach;?></tbody></table></section>
    <?php elseif ($page === 'assignments' && $current['role']==='admin'):
        $mentorStats=fetch_all($db,"SELECT u.id,u.full_name,u.department,u.position,COUNT(DISTINCT p.user_id) interns,COUNT(t.id) total_tasks,SUM(CASE WHEN t.status='Выполнено' THEN 1 ELSE 0 END) done_tasks FROM users u LEFT JOIN intern_profiles p ON p.mentor_id=u.id LEFT JOIN tasks t ON t.intern_id=p.user_id WHERE u.role='mentor' GROUP BY u.id ORDER BY u.full_name");
        $allInterns=fetch_all($db,"SELECT u.id,p.mentor_id FROM users u JOIN intern_profiles p ON p.user_id=u.id WHERE u.role='intern'");
        $statuses=fetch_all($db,'SELECT DISTINCT status FROM intern_profiles ORDER BY status');
        $filterMentor=$_GET['mentor'] ?? 'all'; $filterStatus=trim((string)($_GET['status'] ?? '')); $search=trim((string)($_GET['q'] ?? ''));
        $where=[]; $params=[];
        if($filterMentor==='none'){$where[]='p.mentor_id IS NULL';} elseif($filterMentor!=='all' && ctype_digit((string)$filterMentor)){$where[]='p.mentor_id=?';$params[]=(int)$filterMentor;}
        if($filterStatus!==''){$where[]='p.status=?';$params[]=$filterStatus;}
        if($search!==''){$where[]='(u.full_name LIKE ? OR u.email LIKE ? OR p.practice_topic LIKE ? OR p.university LIKE ?)';$params[]='%'.$search.'%';$params[]='%'.$search.'%';$params[]='%'.$search.'%';$params[]='%'.$search.'%';}
        $interns=fetch_all($db,"SELECT u.id,u.full_name,u.email,p.university,p.specialty,p.course,p.group_name,p.practice_topic,p.start_date,p.end_date,p.status,p.mentor_id,m.full_name mentor_name,m.department mentor_department,(SELECT COUNT(*) FROM tasks WHERE intern_id=u.id) total_tasks,(SELECT SUM(CASE WHEN status='Выполнено' THEN 1 ELSE 0 END) FROM tasks WHERE intern_id=u.id) done_tasks,(SELECT COUNT(*) FROM reports WHERE intern_id=u.id AND status='На проверке') pending_reports,(SELECT COUNT(*) FROM diary_entries WHERE intern_id=u.id AND status='На проверке') pending_diary FROM users u JOIN intern_profiles p ON p.user_id=u.id LEFT JOIN users m ON m.id=p.mentor_id WHERE u.role='intern'".($where?' AND '.implode(' AND ',$where):'').' ORDER BY CASE WHEN p.mentor_id IS NULL THEN 0 ELSE 1 END,u.full_name',$params);
        foreach($interns as &$i){$i['progress']=progress($db,(int)$i['id']);} unset($i);
        $totalInterns=count($allInterns); $assignedInterns=count(array_filter($allInterns,fn($i)=>!empty($i['mentor_id']))); $unassignedInterns=$totalInterns-$assignedInterns; $avgProgress=$totalInterns?round(array_sum(array_map(fn($i)=>progress($db,(int)$i['id']),$allInterns))/$totalInterns):0; ?>
        <div class="stat-grid assignment-stats"><article class="stat"><span>Практикантов всего</span><strong><?=$totalInterns?></strong></article><article class="stat"><span>Назначены руководителю</span><strong><?=$assignedInterns?></strong></article><article class="stat"><span>Без руководителя</span><strong><?=$unassignedInterns?></strong></article><article class="stat"><span>Средний прогресс</span><strong><?=$avgProgress?>%</strong></article></div>
        <section class="panel assignment-tools"><div class="panel-head"><div><h2>Управление назначениями</h2><p class="muted">Фильтруйте практикантов, меняйте руководителя точечно или отметьте несколько человек для массового назначения.</p></div><span class="badge">Найдено: <?=count($interns)?></span></div><form class="assignment-filter" method="get"><input type="hidden" name="page" value="assignments"><label>Поиск<input name="q" value="<?=e($search)?>" placeholder="ФИО, email, тема или вуз"></label><label>Руководитель<select name="mentor"><option value="all">Все назначения</option><option value="none" <?=$filterMentor==='none'?'selected':''?>>Без руководителя</option><?php foreach($mentors as $m):?><option value="<?=$m['id']?>" <?=$filterMentor===(string)$m['id']?'selected':''?>><?=e($m['full_name'])?></option><?php endforeach;?></select></label><label>Статус<select name="status"><option value="">Все статусы</option><?php foreach($statuses as $s):?><option value="<?=e($s['status'])?>" <?=$filterStatus===$s['status']?'selected':''?>><?=e($s['status'])?></option><?php endforeach;?></select></label><button class="button" type="submit">Показать</button><a class="button secondary" href="index.php?page=assignments">Сбросить</a></form></section>
        <section class="panel bulk-panel"><div><h2>Массовое назначение</h2><p class="muted">Отметьте практикантов в списке ниже, выберите руководителя и сохраните изменения одним действием.</p></div><form id="bulkAssignForm" class="bulk-actions" method="post"><input type="hidden" name="action" value="assign_bulk"><?= csrf_field() ?><label>Назначить руководителя<select name="mentor_id" required <?=!$mentors?'disabled':''?>><option value="">Выберите руководителя</option><?php foreach($mentors as $m):?><option value="<?=$m['id']?>"><?=e($m['full_name'].' — '.$m['department'])?></option><?php endforeach;?></select></label><label class="check-row"><input type="checkbox" name="transfer_tasks" value="1" checked> Перенести активные задания</label><button class="button" type="submit" <?=!$mentors?'disabled':''?>>Назначить выбранных</button></form></section>
        <div class="mentor-board"><?php foreach($mentorStats as $m): $done=(int)($m['done_tasks'] ?? 0); $total=(int)$m['total_tasks']; $loadProgress=$total?round($done/$total*100):0;?><article class="mentor-card"><span class="badge"><?=e($m['department'] ?: 'Руководитель')?></span><h3><?=e($m['full_name'])?></h3><p><?=e($m['position'] ?: 'Ответственный за практику')?></p><div class="mentor-load"><b><?= (int)$m['interns'] ?></b><span>практикантов</span></div><div class="progress compact"><i style="width:<?=$loadProgress?>%"></i></div><small><?=$done?> из <?=$total?> заданий выполнено</small></article><?php endforeach;?><?php if(!$mentorStats):?><div class="empty">Руководителей пока нет.</div><?php endif;?></div>
        <div class="assignment-list"><?php foreach($interns as $i): $isUnassigned=empty($i['mentor_id']); $pending=(int)$i['pending_reports']+(int)$i['pending_diary'];?><article class="assignment-card <?=$isUnassigned?'needs-mentor':''?>"><label class="assign-check"><input type="checkbox" form="bulkAssignForm" name="intern_ids[]" value="<?=$i['id']?>"><span>Выбрать</span></label><div class="assignment-main"><div class="assignment-title"><div><span class="badge"><?=e($i['status'])?></span><h3><?=e($i['full_name'])?></h3></div><strong><?=$i['progress']?>%</strong></div><p><?=e($i['practice_topic'])?></p><div class="assignment-meta"><span><?=e($i['university'])?></span><span><?=e($i['specialty'])?>, <?=e((string)$i['course'])?> курс<?= $i['group_name'] ? ', '.e($i['group_name']) : '' ?></span><span><?=e($i['start_date'])?> — <?=e($i['end_date'])?></span></div><div class="progress"><i style="width:<?=$i['progress']?>%"></i></div><div class="assignment-current"><span>Сейчас</span><b><?=e($i['mentor_name'] ?: 'руководитель не назначен')?></b><?php if($i['mentor_department']):?><small><?=e($i['mentor_department'])?></small><?php endif;?></div><small>Заданий: <?= (int)$i['done_tasks'] ?> / <?= (int)$i['total_tasks'] ?> · На проверке: <?=$pending?></small></div><form class="assignment-form" method="post"><input type="hidden" name="action" value="assign_mentor"><?= csrf_field() ?><input type="hidden" name="intern_id" value="<?=$i['id']?>"><label>Новый руководитель<select name="mentor_id" <?=!$mentors?'disabled':''?>><option value="">Без руководителя</option><?php foreach($mentors as $m):?><option value="<?=$m['id']?>" <?=$m['id']==$i['mentor_id']?'selected':''?>><?=e($m['full_name'].' — '.$m['department'])?></option><?php endforeach;?></select></label><label class="check-row"><input type="checkbox" name="transfer_tasks" value="1" checked> Перенести активные задания</label><button class="button small" type="submit" <?=!$mentors?'disabled':''?>>Сохранить</button></form></article><?php endforeach;?><?php if(!$interns):?><div class="empty">По выбранным условиям практикантов не найдено.</div><?php endif;?></div>
    <?php endif; ?>
<?php endif; ?>
</main>
<footer class="site-footer">
    <div class="footer-main">
        <div class="footer-brand"><img src="assets/orenburg-emblem.webp" alt=""><div><b>Практика.Цифра</b></div></div>
        <nav class="footer-links">
            <?php foreach (nav_items(user()) as $key => $label): ?>
                <a href="index.php?page=<?= e($key) ?>"><?= e($label) ?></a>
            <?php endforeach; ?>
        </nav>
        <div class="footer-contact"><span>Минцифра Оренбургской области</span></div>
    </div>
</footer>
<div class="cookie-banner" data-cookie-banner hidden>
    <div>
        <b>Мы используем файлы cookie</b>
        <p>Cookie помогают сохранять вход в личный кабинет и корректно работать с формами сайта.</p>
    </div>
    <button class="button small" type="button" data-cookie-accept>Понятно</button>
</div>
<script src="assets/app.js?v=20260607-security-hardening"></script>
</body></html>
<?php
function render_intern_table(PDO $db, array $interns, bool $withConclusion = false): void { ?>
<div class="table-wrap"><table><thead><tr><th>Практикант</th><th>Тема</th><th>Период</th><th>Прогресс</th><th>Статус</th><?= $withConclusion?'<th>Заключение</th>':''?></tr></thead><tbody><?php foreach($interns as $i): $p=progress($db,(int)$i['id']);?><tr><td><a class="intern-link" href="index.php?page=intern_detail&id=<?=$i['id']?>"><?=e($i['full_name'])?></a><small><?=e($i['specialty'])?></small></td><td><?=e($i['practice_topic'])?></td><td><?=e($i['start_date'])?><small>до <?=e($i['end_date'])?></small></td><td><div class="progress compact"><i style="width:<?=$p?>%"></i></div><small><?=$p?>%</small></td><td><span class="badge"><?=e($i['status'])?></span></td><?php if($withConclusion):?><td><details><summary>Заполнить</summary><form class="mini-form" method="post"><input type="hidden" name="action" value="finalize"><?= csrf_field() ?><input type="hidden" name="intern_id" value="<?=$i['id']?>"><input name="final_grade" placeholder="Оценка" required><textarea name="conclusion" placeholder="Заключение" required></textarea><button class="button small">Сохранить</button></form></details></td><?php endif;?></tr><?php endforeach;?></tbody></table><?php if(!$interns):?><div class="empty">Закреплённых практикантов пока нет.</div><?php endif;?></div><?php }
