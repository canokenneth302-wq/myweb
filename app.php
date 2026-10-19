<?php
declare(strict_types=1);

$config = require __DIR__ . '/config.php';

function db(): PDO
{
    static $pdo;
    global $config;

    if (!$pdo instanceof PDO) {
        $dsn = sprintf(
            'mysql:host=%s;dbname=%s;charset=utf8mb4',
            $config['db_host'],
            $config['db_name']
        );
        $pdo = new PDO($dsn, $config['db_user'], $config['db_password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }

    return $pdo;
}

function h(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $page): never
{
    header('Location: index.php?page=' . rawurlencode($page));
    exit;
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrf(): void
{
    $sent = $_POST['csrf_token'] ?? '';
    if (!is_string($sent) || !hash_equals(csrfToken(), $sent)) {
        http_response_code(400);
        exit('This form has expired. Go back, refresh the page, and try again.');
    }
}

function csrfField(): string
{
    return '<input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '">';
}

function setFlash(string $type, string $message): void
{
    $_SESSION['flash'] = ['type' => $type, 'message' => $message];
}

function takeFlash(): ?array
{
    $flash = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return is_array($flash) ? $flash : null;
}

function currentStudent(): ?array
{
    if (empty($_SESSION['user_id'])) {
        return null;
    }

    $statement = db()->prepare(
        'SELECT u.user_id, u.email, s.student_id, s.first_name, s.middle_name, s.last_name,
                s.birthdate, s.sex, s.address, s.contact_no, s.guardian_name, s.guardian_no,
                s.program_id, s.year_level, p.program_code, p.program_name
         FROM users u
         JOIN students s ON s.user_id = u.user_id
         JOIN programs p ON p.program_id = s.program_id
         WHERE u.user_id = :user_id AND u.role = "student"
         LIMIT 1'
    );
    $statement->execute(['user_id' => (int) $_SESSION['user_id']]);
    $student = $statement->fetch();

    return $student ?: null;
}

function requireStudent(): array
{
    $student = currentStudent();
    if ($student === null) {
        unset($_SESSION['user_id']);
        redirect('login');
    }
    return $student;
}

function activeTerm(): ?array
{
    $statement = db()->query(
        'SELECT term_id, school_year, semester, enroll_start, enroll_end
         FROM terms WHERE is_active = 1 ORDER BY term_id DESC LIMIT 1'
    );
    $term = $statement->fetch();
    return $term ?: null;
}

function currentEnrollment(int $studentId, int $termId): ?array
{
    $statement = db()->prepare(
        'SELECT enrollment_id, status, remarks, appointment_at, submitted_at
         FROM enrollments WHERE student_id = :student_id AND term_id = :term_id LIMIT 1'
    );
    $statement->execute(['student_id' => $studentId, 'term_id' => $termId]);
    $enrollment = $statement->fetch();
    return $enrollment ?: null;
}

function offeredSubjects(int $programId, int $yearLevel, int $termId): array
{
    $statement = db()->prepare(
        'SELECT sub.subject_id, sub.subject_code, sub.subject_name, sub.units,
                sec.section_id, sec.section_name, sec.day_pattern, sec.start_time, sec.end_time,
                sec.room, sec.instructor, sec.max_slots,
                (SELECT COUNT(*) FROM enrollment_items ei
                 JOIN enrollments e ON e.enrollment_id = ei.enrollment_id
                 WHERE ei.section_id = sec.section_id
                   AND e.status IN ("pending", "approved", "enrolled")) AS occupied_slots
         FROM subjects sub
         JOIN sections sec ON sec.subject_id = sub.subject_id AND sec.term_id = :term_id
         WHERE sub.program_id = :program_id AND sub.year_level = :year_level
         ORDER BY sub.subject_code, sec.section_name'
    );
    $statement->execute([
        'program_id' => $programId,
        'year_level' => $yearLevel,
        'term_id' => $termId,
    ]);

    $subjects = [];
    foreach ($statement->fetchAll() as $row) {
        $id = (int) $row['subject_id'];
        if (!isset($subjects[$id])) {
            $subjects[$id] = [
                'subject_id' => $id,
                'subject_code' => $row['subject_code'],
                'subject_name' => $row['subject_name'],
                'units' => (int) $row['units'],
                'sections' => [],
            ];
        }
        $subjects[$id]['sections'][] = $row;
    }
    return array_values($subjects);
}

function chosenSections(int $enrollmentId): array
{
    $statement = db()->prepare(
        'SELECT sec.section_id, sec.section_name, sec.day_pattern, sec.start_time, sec.end_time,
                sec.room, sec.instructor, sub.subject_code, sub.subject_name, sub.units
         FROM enrollment_items ei
         JOIN sections sec ON sec.section_id = ei.section_id
         JOIN subjects sub ON sub.subject_id = sec.subject_id
         WHERE ei.enrollment_id = :enrollment_id
         ORDER BY sub.subject_code, sec.section_name'
    );
    $statement->execute(['enrollment_id' => $enrollmentId]);
    return $statement->fetchAll();
}

function dayTokens(string $pattern): array
{
    preg_match_all('/Th|Su|M|T|W|F|S/', $pattern, $matches);
    return $matches[0];
}

function hasScheduleConflict(array $sections): bool
{
    for ($i = 0, $count = count($sections); $i < $count; $i++) {
        for ($j = $i + 1; $j < $count; $j++) {
            $sharedDays = array_intersect(
                dayTokens((string) $sections[$i]['day_pattern']),
                dayTokens((string) $sections[$j]['day_pattern'])
            );
            if ($sharedDays !== []
                && $sections[$i]['start_time'] < $sections[$j]['end_time']
                && $sections[$i]['end_time'] > $sections[$j]['start_time']) {
                return true;
            }
        }
    }
    return false;
}

function formatTime(string $time): string
{
    $timestamp = strtotime($time);
    return $timestamp === false ? $time : date('g:i A', $timestamp);
}

function statusLabel(string $status): string
{
    return match ($status) {
        'draft' => 'Draft',
        'pending' => 'Awaiting review',
        'approved' => 'Approved',
        'rejected' => 'Needs attention',
        'enrolled' => 'Enrolled',
        default => ucfirst($status),
    };
}

function normalizePhilippineMobile(string $phone): string
{
    $phone = preg_replace('/[\s().-]/', '', trim($phone)) ?? '';
    if (preg_match('/^09\d{9}$/', $phone)) {
        return $phone;
    }
    if (preg_match('/^(?:\+?63)9\d{9}$/', $phone)) {
        return '0' . substr($phone, -10);
    }
    throw new DomainException('The student contact number is not a valid Philippine mobile number. Update the profile before sending SMS.');
}

function sendSemaphoreSms(string $phone, string $message): void
{
    global $config;
    $apiKey = (string) ($config['semaphore_api_key'] ?? '');
    if ($apiKey === '') {
        throw new DomainException('Enrollment approved, but SMS was not sent. Set the SEMAPHORE_API_KEY environment variable first.');
    }
    if (!function_exists('curl_init')) {
        throw new DomainException('Enrollment approved, but SMS was not sent. Enable the PHP cURL extension first.');
    }

    $payload = [
        'apikey' => $apiKey,
        'number' => normalizePhilippineMobile($phone),
        'message' => $message,
    ];
    $senderName = (string) ($config['semaphore_sender_name'] ?? '');
    if ($senderName !== '') {
        $payload['sendername'] = $senderName;
    }

    $handle = curl_init('https://api.semaphore.co/api/v4/messages');
    if ($handle === false) {
        throw new RuntimeException('Unable to initialize the Semaphore SMS request.');
    }
    curl_setopt_array($handle, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 20,
    ]);
    $response = curl_exec($handle);
    $httpStatus = (int) curl_getinfo($handle, CURLINFO_HTTP_CODE);
    $curlError = curl_error($handle);
    curl_close($handle);

    if ($response === false) {
        error_log('Semaphore SMS transport error: ' . $curlError);
        throw new DomainException('Enrollment approved, but Semaphore could not be reached. Check the server connection and retry SMS.');
    }

    $result = json_decode($response, true);
    if ($httpStatus < 200 || $httpStatus >= 300 || !is_array($result) || $result === []) {
        throw new DomainException('Enrollment approved, but Semaphore did not accept the SMS request (HTTP ' . $httpStatus . '). Check your API key/account and retry SMS.');
    }
    $messages = array_is_list($result) ? $result : [$result];
    foreach ($messages as $messageResult) {
        if (!is_array($messageResult)) {
            continue;
        }
        $providerStatus = strtolower((string) ($messageResult['status'] ?? ''));
        if (in_array($providerStatus, ['failed', 'error'], true) || isset($messageResult['error'])) {
            throw new DomainException('Enrollment approved, but Semaphore reported that the SMS failed. Check the Semaphore dashboard and retry SMS.');
        }
    }
}

function limitText(string $value, int $max, string $label, bool $required = false): string
{
    $value = trim($value);
    if ($required && $value === '') {
        throw new DomainException($label . ' is required.');
    }
    if (strlen($value) > $max) {
        throw new DomainException($label . ' must be no more than ' . $max . ' characters.');
    }
    return $value;
}
