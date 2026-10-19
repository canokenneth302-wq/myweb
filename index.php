<?php
declare(strict_types=1);

session_name('campus_enrollment');
session_set_cookie_params([
    'httponly' => true,
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'samesite' => 'Lax',
    'path' => '/',
]);
session_start();
require __DIR__ . '/app.php';

$page = isset($_GET['page']) && is_string($_GET['page']) ? $_GET['page'] : 'dashboard';
$allowedPages = ['login', 'register', 'dashboard', 'enrollment', 'status', 'payments', 'profile'];
if (!in_array($page, $allowedPages, true)) {
    $page = 'dashboard';
}

$student = null;
$term = null;
$enrollment = null;
$flash = null;
$error = '';

try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        verifyCsrf();
        $action = is_string($_POST['action'] ?? null) ? $_POST['action'] : '';

        if ($action === 'login') {
            $email = strtolower(trim((string) ($_POST['email'] ?? '')));
            $password = (string) ($_POST['password'] ?? '');
            $statement = db()->prepare(
                'SELECT user_id, password_hash, role FROM users WHERE email = :email LIMIT 1'
            );
            $statement->execute(['email' => $email]);
            $user = $statement->fetch();
            if (!$user || $user['role'] !== 'student' || !password_verify($password, $user['password_hash'])) {
                throw new DomainException('We could not sign in with those details. Check your email and password.');
            }
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int) $user['user_id'];
            unset($_SESSION['csrf_token']);
            setFlash('success', 'Welcome back. Your enrollment space is ready.');
            redirect('dashboard');
        }

        if ($action === 'register') {
            $email = strtolower(trim((string) ($_POST['email'] ?? '')));
            $password = (string) ($_POST['password'] ?? '');
            $firstName = limitText((string) ($_POST['first_name'] ?? ''), 60, 'First name', true);
            $middleName = limitText((string) ($_POST['middle_name'] ?? ''), 60, 'Middle name');
            $lastName = limitText((string) ($_POST['last_name'] ?? ''), 60, 'Last name', true);
            $birthdate = (string) ($_POST['birthdate'] ?? '');
            $sex = (string) ($_POST['sex'] ?? '');
            $address = limitText((string) ($_POST['address'] ?? ''), 255, 'Address');
            $contact = limitText((string) ($_POST['contact_no'] ?? ''), 20, 'Contact number');
            $guardian = limitText((string) ($_POST['guardian_name'] ?? ''), 120, 'Guardian name');
            $guardianNo = limitText((string) ($_POST['guardian_no'] ?? ''), 20, 'Guardian contact');
            $programId = filter_var($_POST['program_id'] ?? null, FILTER_VALIDATE_INT);
            $yearLevel = filter_var($_POST['year_level'] ?? null, FILTER_VALIDATE_INT);
            $date = DateTime::createFromFormat('!Y-m-d', $birthdate);

            if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 120) {
                throw new DomainException('Enter a valid email address (up to 120 characters).');
            }
            if (strlen($password) < 10 || strlen($password) > 200) {
                throw new DomainException('Your password must be between 10 and 200 characters.');
            }
            if (!$date || $date->format('Y-m-d') !== $birthdate || $date >= new DateTime('today')) {
                throw new DomainException('Enter a valid birth date in the past.');
            }
            if (!in_array($sex, ['M', 'F'], true)) {
                throw new DomainException('Choose one of the listed sex options.');
            }
            if (!$programId || !$yearLevel || $yearLevel < 1 || $yearLevel > 6) {
                throw new DomainException('Choose a valid program and year level.');
            }
            $programCheck = db()->prepare('SELECT program_id FROM programs WHERE program_id = :id');
            $programCheck->execute(['id' => $programId]);
            if (!$programCheck->fetch()) {
                throw new DomainException('Choose one of the available programs.');
            }

            $pdo = db();
            $pdo->beginTransaction();
            try {
                $userInsert = $pdo->prepare(
                    'INSERT INTO users (email, password_hash, role)
                     VALUES (:email, :password_hash, "student")'
                );
                $userInsert->execute([
                    'email' => $email,
                    'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                ]);
                $userId = (int) $pdo->lastInsertId();
                $studentInsert = $pdo->prepare(
                    'INSERT INTO students
                     (user_id, first_name, middle_name, last_name, birthdate, sex, address,
                      contact_no, guardian_name, guardian_no, program_id, year_level)
                     VALUES
                     (:user_id, :first_name, :middle_name, :last_name, :birthdate, :sex,
                      :address, :contact_no, :guardian_name, :guardian_no, :program_id, :year_level)'
                );
                $studentInsert->execute([
                    'user_id' => $userId,
                    'first_name' => $firstName,
                    'middle_name' => $middleName !== '' ? $middleName : null,
                    'last_name' => $lastName,
                    'birthdate' => $birthdate,
                    'sex' => $sex,
                    'address' => $address !== '' ? $address : null,
                    'contact_no' => $contact !== '' ? $contact : null,
                    'guardian_name' => $guardian !== '' ? $guardian : null,
                    'guardian_no' => $guardianNo !== '' ? $guardianNo : null,
                    'program_id' => $programId,
                    'year_level' => $yearLevel,
                ]);
                $pdo->commit();
            } catch (Throwable $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                if ($exception instanceof PDOException && (string) $exception->getCode() === '23000') {
                    throw new DomainException('That email is already registered. Please sign in instead.');
                }
                throw $exception;
            }

            session_regenerate_id(true);
            $_SESSION['user_id'] = $userId;
            unset($_SESSION['csrf_token']);
            setFlash('success', 'Your student account has been created.');
            redirect('dashboard');
        }

        $student = requireStudent();
        if ($action === 'logout') {
            $_SESSION = [];
            if (ini_get('session.use_cookies')) {
                $cookie = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000, $cookie['path'], '', $cookie['secure'], $cookie['httponly']);
            }
            session_destroy();
            header('Location: index.php?page=login');
            exit;
        }

        if ($action === 'save_profile') {
            $firstName = limitText((string) ($_POST['first_name'] ?? ''), 60, 'First name', true);
            $middleName = limitText((string) ($_POST['middle_name'] ?? ''), 60, 'Middle name');
            $lastName = limitText((string) ($_POST['last_name'] ?? ''), 60, 'Last name', true);
            $birthdate = (string) ($_POST['birthdate'] ?? '');
            $sex = (string) ($_POST['sex'] ?? '');
            $date = DateTime::createFromFormat('!Y-m-d', $birthdate);
            if (!$date || $date->format('Y-m-d') !== $birthdate || $date >= new DateTime('today')) {
                throw new DomainException('Enter a valid birth date in the past.');
            }
            if (!in_array($sex, ['M', 'F'], true)) {
                throw new DomainException('Choose one of the listed sex options.');
            }
            $update = db()->prepare(
                'UPDATE students SET first_name = :first_name, middle_name = :middle_name,
                 last_name = :last_name, birthdate = :birthdate, sex = :sex, address = :address,
                 contact_no = :contact_no, guardian_name = :guardian_name, guardian_no = :guardian_no
                 WHERE student_id = :student_id'
            );
            $update->execute([
                'first_name' => $firstName,
                'middle_name' => $middleName !== '' ? $middleName : null,
                'last_name' => $lastName,
                'birthdate' => $birthdate,
                'sex' => $sex,
                'address' => ($value = limitText((string) ($_POST['address'] ?? ''), 255, 'Address')) !== '' ? $value : null,
                'contact_no' => ($value = limitText((string) ($_POST['contact_no'] ?? ''), 20, 'Contact number')) !== '' ? $value : null,
                'guardian_name' => ($value = limitText((string) ($_POST['guardian_name'] ?? ''), 120, 'Guardian name')) !== '' ? $value : null,
                'guardian_no' => ($value = limitText((string) ($_POST['guardian_no'] ?? ''), 20, 'Guardian contact')) !== '' ? $value : null,
                'student_id' => (int) $student['student_id'],
            ]);
            setFlash('success', 'Your profile has been updated.');
            redirect('profile');
        }

        if ($action === 'save_enrollment' || $action === 'submit_enrollment') {
            $term = activeTerm();
            if (!$term) {
                throw new DomainException('There is no active enrollment term right now.');
            }
            $subjects = offeredSubjects((int) $student['program_id'], (int) $student['year_level'], (int) $term['term_id']);
            if ($subjects === []) {
                throw new DomainException('There are no sections currently offered for your program and year.');
            }
            $availableIds = [];
            foreach ($subjects as $subject) {
                foreach ($subject['sections'] as $section) {
                    $availableIds[(int) $section['section_id']] = (int) $subject['subject_id'];
                }
            }

            $rawSelections = $_POST['sections'] ?? [];
            if (!is_array($rawSelections)) {
                throw new DomainException('Please choose sections using the enrollment form.');
            }
            $selected = [];
            foreach ($rawSelections as $subjectId => $sectionId) {
                if (!is_scalar($subjectId) || !is_scalar($sectionId)) {
                    throw new DomainException('One or more section selections are invalid.');
                }
                $subjectId = filter_var($subjectId, FILTER_VALIDATE_INT);
                $sectionId = filter_var($sectionId, FILTER_VALIDATE_INT);
                if (!$subjectId || !$sectionId) {
                    continue;
                }
                if (!isset($availableIds[$sectionId]) || $availableIds[$sectionId] !== $subjectId) {
                    throw new DomainException('One of your selected sections is no longer available.');
                }
                $selected[] = $sectionId;
            }
            if (count($selected) !== count(array_unique($selected))) {
                throw new DomainException('A section cannot be selected more than once.');
            }

            $selectedRows = [];
            if ($selected !== []) {
                $placeholders = implode(',', array_fill(0, count($selected), '?'));
                $selectedQuery = db()->prepare(
                    'SELECT section_id, subject_id, day_pattern, start_time, end_time, max_slots
                     FROM sections WHERE term_id = ? AND section_id IN (' . $placeholders . ')
                     ORDER BY section_id'
                );
                $selectedQuery->execute(array_merge([(int) $term['term_id']], $selected));
                $selectedRows = $selectedQuery->fetchAll();
                if (count($selectedRows) !== count($selected)) {
                    throw new DomainException('One of your selected sections is no longer offered.');
                }
                if (count(array_unique(array_column($selectedRows, 'subject_id'))) !== count($selectedRows)) {
                    throw new DomainException('Choose only one section for each subject.');
                }
                if (hasScheduleConflict($selectedRows)) {
                    throw new DomainException('Those class times overlap. Choose a different section before saving.');
                }
            }
            if ($action === 'submit_enrollment' && count($selectedRows) !== count($subjects)) {
                throw new DomainException('Choose one section for every offered subject before submitting.');
            }

            $pdo = db();
            $pdo->beginTransaction();
            try {
                $enrollmentQuery = $pdo->prepare(
                    'SELECT enrollment_id, status FROM enrollments
                     WHERE student_id = :student_id AND term_id = :term_id FOR UPDATE'
                );
                $enrollmentQuery->execute([
                    'student_id' => (int) $student['student_id'],
                    'term_id' => (int) $term['term_id'],
                ]);
                $existing = $enrollmentQuery->fetch();
                if ($existing && $existing['status'] !== 'draft') {
                    throw new DomainException('This enrollment has already been submitted and can no longer be edited.');
                }
                if ($existing) {
                    $enrollmentId = (int) $existing['enrollment_id'];
                } else {
                    $create = $pdo->prepare(
                        'INSERT INTO enrollments (student_id, term_id, status)
                         VALUES (:student_id, :term_id, "draft")'
                    );
                    $create->execute([
                        'student_id' => (int) $student['student_id'],
                        'term_id' => (int) $term['term_id'],
                    ]);
                    $enrollmentId = (int) $pdo->lastInsertId();
                }

                if ($action === 'submit_enrollment') {
                    foreach ($selectedRows as $row) {
                        $lock = $pdo->prepare(
                            'SELECT max_slots FROM sections WHERE section_id = :section_id FOR UPDATE'
                        );
                        $lock->execute(['section_id' => (int) $row['section_id']]);
                        $capacity = $lock->fetch();
                        $occupiedQuery = $pdo->prepare(
                            'SELECT COUNT(*) FROM enrollment_items ei
                             JOIN enrollments e ON e.enrollment_id = ei.enrollment_id
                             WHERE ei.section_id = :section_id
                               AND e.status IN ("pending", "approved", "enrolled")'
                        );
                        $occupiedQuery->execute(['section_id' => (int) $row['section_id']]);
                        if (!$capacity || (int) $occupiedQuery->fetchColumn() >= (int) $capacity['max_slots']) {
                            throw new DomainException('A selected section has filled while you were choosing. Review available sections and try again.');
                        }
                    }
                }

                $delete = $pdo->prepare('DELETE FROM enrollment_items WHERE enrollment_id = :id');
                $delete->execute(['id' => $enrollmentId]);
                $insert = $pdo->prepare(
                    'INSERT INTO enrollment_items (enrollment_id, section_id) VALUES (:enrollment_id, :section_id)'
                );
                foreach ($selected as $sectionId) {
                    $insert->execute(['enrollment_id' => $enrollmentId, 'section_id' => $sectionId]);
                }
                if ($action === 'submit_enrollment') {
                    $submit = $pdo->prepare(
                        'UPDATE enrollments SET status = "pending", submitted_at = NOW()
                         WHERE enrollment_id = :id AND status = "draft"'
                    );
                    $submit->execute(['id' => $enrollmentId]);
                    $notice = $pdo->prepare(
                        'INSERT INTO notifications (user_id, message) VALUES (:user_id, :message)'
                    );
                    $notice->execute([
                        'user_id' => (int) $student['user_id'],
                        'message' => 'Your enrollment form has been submitted for registrar review.',
                    ]);
                }
                $pdo->commit();
            } catch (Throwable $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                throw $exception;
            }
            setFlash('success', $action === 'submit_enrollment'
                ? 'Enrollment submitted. You can follow its progress from your portal.'
                : 'Your enrollment selections have been saved as a draft.');
            redirect($action === 'submit_enrollment' ? 'status' : 'enrollment');
        }

        if ($action === 'submit_payment') {
            $term = activeTerm();
            $enrollment = $term ? currentEnrollment((int) $student['student_id'], (int) $term['term_id']) : null;
            if (!$enrollment || !in_array($enrollment['status'], ['pending', 'approved', 'enrolled'], true)) {
                throw new DomainException('Submit an enrollment before recording payment details.');
            }
            $amountText = trim((string) ($_POST['amount'] ?? ''));
            if (!preg_match('/^\d{1,8}(?:\.\d{1,2})?$/', $amountText) || (float) $amountText <= 0) {
                throw new DomainException('Enter a valid payment amount greater than zero.');
            }
            $method = (string) ($_POST['method'] ?? '');
            if (!in_array($method, ['gcash', 'maya', 'bank', 'cash'], true)) {
                throw new DomainException('Choose one of the listed payment methods.');
            }
            $reference = limitText((string) ($_POST['reference_no'] ?? ''), 60, 'Reference number');
            $pdo = db();
            $pdo->beginTransaction();
            $insertPayment = $pdo->prepare(
                'INSERT INTO payments (enrollment_id, amount, method, reference_no, status)
                 VALUES (:enrollment_id, :amount, :method, :reference_no, "pending")'
            );
            $insertPayment->execute([
                'enrollment_id' => (int) $enrollment['enrollment_id'],
                'amount' => $amountText,
                'method' => $method,
                'reference_no' => $reference !== '' ? $reference : null,
            ]);
            $notice = $pdo->prepare(
                'INSERT INTO notifications (user_id, message) VALUES (:user_id, :message)'
            );
            $notice->execute([
                'user_id' => (int) $student['user_id'],
                'message' => 'Your payment details have been recorded and are awaiting cashier review.',
            ]);
            $pdo->commit();
            setFlash('success', 'Payment details recorded. This is not a real payment transaction.');
            redirect('payments');
        }

        throw new DomainException('That action is not available.');
    }

    if (in_array($page, ['dashboard', 'enrollment', 'status', 'payments', 'profile'], true)) {
        $student = requireStudent();
        $term = activeTerm();
        $enrollment = $term ? currentEnrollment((int) $student['student_id'], (int) $term['term_id']) : null;
    }
} catch (DomainException $exception) {
    $error = $exception->getMessage();
} catch (PDOException $exception) {
    error_log('Online enrollment database error: ' . $exception->getMessage());
    $error = 'We could not complete that request right now. Please try again in a moment.';
} catch (Throwable $exception) {
    error_log('Online enrollment error: ' . $exception->getMessage());
    $error = 'Something unexpected happened. Please try again.';
}

if ($student === null && in_array($page, ['dashboard', 'enrollment', 'status', 'payments', 'profile'], true)) {
    if (empty($_SESSION['user_id'])) {
        $page = 'login';
    } else {
        $page = 'login';
    }
}
$flash = takeFlash();
$programs = [];
if ($page === 'register' || $page === 'profile') {
    $programs = db()->query('SELECT program_id, program_code, program_name FROM programs ORDER BY program_code')->fetchAll();
}
$notifications = [];
if ($student) {
    $notificationQuery = db()->prepare(
        'SELECT message, is_read, created_at FROM notifications
         WHERE user_id = :user_id ORDER BY created_at DESC, notif_id DESC LIMIT 5'
    );
    $notificationQuery->execute(['user_id' => (int) $student['user_id']]);
    $notifications = $notificationQuery->fetchAll();
}
$pageTitle = [
    'login' => 'Sign in',
    'register' => 'Create account',
    'dashboard' => 'My campus',
    'enrollment' => 'Choose classes',
    'status' => 'Enrollment status',
    'payments' => 'Payment details',
    'profile' => 'My profile',
][$page];
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#17392f">
    <title><?= h($pageTitle) ?> · Northfield Student Portal</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body class="<?= $student ? 'has-sidebar' : 'auth-page' ?>">
<?php if ($student): ?>
    <aside class="sidebar">
        <a class="brand" href="index.php" aria-label="Northfield Student Portal home">
            <span class="brand-mark" aria-hidden="true">N</span>
            <span><strong>Northfield</strong><small>STUDENT PORTAL</small></span>
        </a>
        <div class="sidebar-student">
            <span class="eyebrow">YOUR SPACE</span>
            <strong><?= h($student['first_name'] . ' ' . $student['last_name']) ?></strong>
            <span><?= h($student['program_code']) ?> · Year <?= (int) $student['year_level'] ?></span>
        </div>
        <nav class="main-nav" aria-label="Main navigation">
            <a class="<?= $page === 'dashboard' ? 'active' : '' ?>" href="index.php?page=dashboard"><span>01</span> Overview</a>
            <a class="<?= $page === 'enrollment' ? 'active' : '' ?>" href="index.php?page=enrollment"><span>02</span> Class selection</a>
            <a class="<?= $page === 'status' ? 'active' : '' ?>" href="index.php?page=status"><span>03</span> Enrollment status</a>
            <a class="<?= $page === 'payments' ? 'active' : '' ?>" href="index.php?page=payments"><span>04</span> Payment details</a>
            <a class="<?= $page === 'profile' ? 'active' : '' ?>" href="index.php?page=profile"><span>05</span> My profile</a>
        </nav>
        <div class="sidebar-foot">
            <span class="term-dot"></span>
            <span>STUDENT SERVICES<br><small>Here to help you move forward</small></span>
        </div>
        <form method="post" class="signout-form">
            <?= csrfField() ?>
            <input type="hidden" name="action" value="logout">
            <button type="submit" class="signout">Sign out <span aria-hidden="true">↗</span></button>
        </form>
    </aside>
<?php else: ?>
    <header class="auth-topbar">
        <a class="brand brand-dark" href="index.php?page=login">
            <span class="brand-mark" aria-hidden="true">N</span>
            <span><strong>Northfield</strong><small>STUDENT PORTAL</small></span>
        </a>
        <span class="auth-top-note">A good term starts with a clear next step.</span>
    </header>
<?php endif; ?>

<main class="<?= $student ? 'main-content' : 'auth-main' ?>">
    <?php if ($flash): ?>
        <div class="notice notice-<?= h($flash['type']) ?>" role="status"><?= h($flash['message']) ?></div>
    <?php endif; ?>
    <?php if ($error !== ''): ?>
        <div class="notice notice-error" role="alert"><?= h($error) ?></div>
    <?php endif; ?>

    <?php if ($page === 'login'): ?>
        <section class="auth-layout">
            <div class="auth-copy">
                <span class="eyebrow">YOUR NEXT CHAPTER</span>
                <h1>Make room<br>for what’s <em>next.</em></h1>
                <p>Your classes, enrollment progress, and important notices—together in one calm place.</p>
                <div class="auth-motto"><span class="motto-rule"></span><span>LEARN WITH PURPOSE<br><small>Northfield College · Student Services</small></span></div>
            </div>
            <div class="auth-form-wrap">
                <span class="eyebrow">WELCOME BACK</span>
                <h2>Sign in to your portal</h2>
                <p class="muted">Use the email address linked to your student account.</p>
                <form method="post" class="form-stack">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="login">
                    <label>Email address<input type="email" name="email" autocomplete="email" maxlength="120" required></label>
                    <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
                    <button class="button button-primary button-wide" type="submit">Sign in <span aria-hidden="true">→</span></button>
                </form>
                <p class="form-switch">New to Northfield? <a href="index.php?page=register">Create a student account</a></p>
            </div>
        </section>
    <?php elseif ($page === 'register'): ?>
        <section class="registration">
            <div class="registration-heading">
                <span class="eyebrow">START HERE</span>
                <h1>Make this place <em>yours.</em></h1>
                <p class="muted">Create a student account to start planning your term. Fields marked required must be completed.</p>
            </div>
            <form method="post" class="profile-form">
                <?= csrfField() ?>
                <input type="hidden" name="action" value="register">
                <fieldset>
                    <legend>Account access</legend>
                    <div class="form-grid">
                        <label class="span-2">Email address <span class="required">Required</span><input type="email" name="email" maxlength="120" autocomplete="email" required></label>
                        <label class="span-2">Password <span class="required">10 characters minimum</span><input type="password" name="password" minlength="10" maxlength="200" autocomplete="new-password" required></label>
                    </div>
                </fieldset>
                <fieldset>
                    <legend>Student profile</legend>
                    <div class="form-grid">
                        <label>First name<input name="first_name" maxlength="60" autocomplete="given-name" required></label>
                        <label>Middle name <span class="optional">Optional</span><input name="middle_name" maxlength="60" autocomplete="additional-name"></label>
                        <label>Last name<input name="last_name" maxlength="60" autocomplete="family-name" required></label>
                        <label>Date of birth<input type="date" name="birthdate" required></label>
                        <label>Sex<select name="sex" required><option value="">Choose…</option><option value="F">Female</option><option value="M">Male</option></select></label>
                        <label>Program<select name="program_id" required><option value="">Choose…</option><?php foreach ($programs as $program): ?><option value="<?= (int) $program['program_id'] ?>"><?= h($program['program_code'] . ' — ' . $program['program_name']) ?></option><?php endforeach; ?></select></label>
                        <label>Year level<select name="year_level" required><option value="">Choose…</option><?php for ($year = 1; $year <= 6; $year++): ?><option value="<?= $year ?>">Year <?= $year ?></option><?php endfor; ?></select></label>
                        <label>Contact number <span class="optional">Optional</span><input name="contact_no" maxlength="20" autocomplete="tel"></label>
                        <label class="span-2">Home address <span class="optional">Optional</span><input name="address" maxlength="255" autocomplete="street-address"></label>
                    </div>
                </fieldset>
                <fieldset>
                    <legend>Guardian contact <span class="optional">Optional</span></legend>
                    <div class="form-grid">
                        <label>Guardian name<input name="guardian_name" maxlength="120"></label>
                        <label>Guardian contact number<input name="guardian_no" maxlength="20"></label>
                    </div>
                </fieldset>
                <div class="form-actions"><a class="text-link" href="index.php?page=login">Already registered? Sign in</a><button class="button button-primary" type="submit">Create account <span aria-hidden="true">→</span></button></div>
            </form>
        </section>
    <?php elseif ($page === 'dashboard' && $student): ?>
        <?php
        $selected = $enrollment ? chosenSections((int) $enrollment['enrollment_id']) : [];
        $paymentQuery = db()->prepare(
            'SELECT amount, method, status, paid_at FROM payments
             WHERE enrollment_id = :enrollment_id ORDER BY paid_at DESC, payment_id DESC LIMIT 3'
        );
        $paymentQuery->execute(['enrollment_id' => (int) ($enrollment['enrollment_id'] ?? 0)]);
        $payments = $enrollment ? $paymentQuery->fetchAll() : [];
        $editable = !$enrollment || $enrollment['status'] === 'draft';
        ?>
        <div class="page-heading">
            <div><span class="eyebrow">STUDENT OVERVIEW</span><h1>Good day, <?= h($student['first_name']) ?>.</h1><p>One step at a time. Here’s where your term stands.</p></div>
            <div class="term-stamp"><span>ACTIVE TERM</span><strong><?= $term ? h($term['school_year'] . ' · ' . $term['semester']) : 'Not set' ?></strong><?php if ($term && $term['enroll_start'] && $term['enroll_end']): ?><small><?= h(date('M j', strtotime($term['enroll_start']))) ?> — <?= h(date('M j, Y', strtotime($term['enroll_end']))) ?></small><?php endif; ?></div>
        </div>
        <?php if (!$term): ?>
            <section class="empty-panel"><span class="empty-symbol">—</span><div><h2>No active term yet</h2><p>Enrollment information will appear here once a term is open.</p></div></section>
        <?php else: ?>
            <section class="progress-band">
                <div class="progress-copy"><span class="eyebrow">YOUR ENROLLMENT</span><h2><?= $enrollment ? h(statusLabel($enrollment['status'])) : 'Ready when you are' ?></h2><p><?= $enrollment && $enrollment['status'] !== 'draft' ? 'Your submission is saved. Watch for an update from the registrar.' : 'Choose a section for each subject, then save or submit your enrollment.' ?></p></div>
                <div class="progress-steps" aria-label="Enrollment steps">
                    <div class="step <?= $enrollment ? 'step-done' : 'step-current' ?>"><b>1</b><span>Choose<br>classes</span></div><span class="step-line <?= $enrollment && $enrollment['status'] !== 'draft' ? 'filled' : '' ?>"></span><div class="step <?= $enrollment && $enrollment['status'] !== 'draft' ? 'step-current' : '' ?>"><b>2</b><span>Registrar<br>review</span></div><span class="step-line <?= $enrollment && in_array($enrollment['status'], ['approved', 'enrolled'], true) ? 'filled' : '' ?>"></span><div class="step <?= $enrollment && $enrollment['status'] === 'enrolled' ? 'step-current' : '' ?>"><b>3</b><span>You're<br>enrolled</span></div>
                </div>
                <a class="button button-light" href="index.php?page=<?= $editable ? 'enrollment' : 'status' ?>"><?= $editable ? ($enrollment ? 'Continue enrollment' : 'Choose classes') : 'View status' ?> <span aria-hidden="true">→</span></a>
            </section>
            <div class="dashboard-grid">
                <section class="content-panel class-panel">
                    <div class="panel-heading"><div><span class="eyebrow">YOUR CLASS PLAN</span><h2>Selected sections</h2></div><a href="index.php?page=<?= $editable ? 'enrollment' : 'status' ?>" class="text-link"><?= $editable ? 'Edit plan' : 'View details' ?> <span aria-hidden="true">↗</span></a></div>
                    <?php if ($selected): ?><div class="class-list"><?php foreach ($selected as $section): ?><div class="class-row"><div class="class-code"><?= h($section['subject_code']) ?></div><div class="class-details"><strong><?= h($section['subject_name']) ?></strong><span><?= h($section['day_pattern']) ?> · <?= h(formatTime($section['start_time']) . '–' . formatTime($section['end_time'])) ?> · <?= h($section['section_name']) ?></span></div><span class="units"><?= (int) $section['units'] ?> u</span></div><?php endforeach; ?></div><?php else: ?><div class="empty-inline"><span>01</span><p>No classes selected yet. Your plan begins with a section choice for each subject.</p><a href="index.php?page=enrollment">Explore available sections →</a></div><?php endif; ?>
                </section>
                <section class="content-panel payment-panel">
                    <div class="panel-heading"><div><span class="eyebrow">PAYMENT RECORD</span><h2>Payment details</h2></div><span class="icon-square" aria-hidden="true">↗</span></div>
                    <?php if ($payments): foreach ($payments as $payment): ?><div class="payment-row"><div><strong><?= h(strtoupper($payment['method'])) ?> <span class="status-pill status-<?= h($payment['status']) ?>"><?= h(ucfirst($payment['status'])) ?></span></strong><small><?= h(date('M j, Y', strtotime($payment['paid_at']))) ?></small></div><b>₱<?= h(number_format((float) $payment['amount'], 2)) ?></b></div><?php endforeach; ?>
                    <?php elseif ($enrollment && in_array($enrollment['status'], ['pending', 'approved', 'enrolled'], true)): ?><p class="muted">No payment details recorded for this term.</p><a href="index.php?page=payments" class="text-link">Record payment details →</a>
                    <?php else: ?><div class="payment-empty"><span>₱</span><p>After you submit enrollment, you can record payment details here for cashier follow-up.</p></div><?php endif; ?>
                    <p class="tiny-note">Payment details are recorded for review; no payment is processed online.</p>
                </section>
                <section class="content-panel notification-panel">
                    <div class="panel-heading"><div><span class="eyebrow">LATEST UPDATES</span><h2>Notifications</h2></div><span class="icon-square" aria-hidden="true">✳</span></div>
                    <?php if ($notifications): ?><ul class="notification-list"><?php foreach ($notifications as $notification): ?><li><span class="notification-dot <?= !(int) $notification['is_read'] ? 'unread' : '' ?>"></span><div><p><?= h($notification['message']) ?></p><small><?= h(date('M j · g:i A', strtotime($notification['created_at']))) ?></small></div></li><?php endforeach; ?></ul><?php else: ?><div class="empty-inline"><span>✳</span><p>When there’s news about your enrollment, it will find you here.</p></div><?php endif; ?>
                </section>
                <aside class="help-note"><span class="eyebrow">A NOTE FROM STUDENT SERVICES</span><p>Need help with a class choice or your student details? Reach out to the registrar before submitting your enrollment.</p><span class="note-signoff">We’re glad you’re here.</span></aside>
            </div>
        <?php endif; ?>
    <?php elseif ($page === 'enrollment' && $student): ?>
        <?php
        $subjects = $term ? offeredSubjects((int) $student['program_id'], (int) $student['year_level'], (int) $term['term_id']) : [];
        $editable = !$enrollment || $enrollment['status'] === 'draft';
        $chosen = $enrollment ? chosenSections((int) $enrollment['enrollment_id']) : [];
        $selectedMap = [];
        foreach ($chosen as $chosenRow) {
            $selectedMap[(int) $chosenRow['section_id']] = true;
        }
        $selectedCount = count($chosen);
        ?>
        <div class="page-heading">
            <div><span class="eyebrow">BUILD YOUR TERM</span><h1>Choose your classes.</h1><p>Pick one section for every offered subject. Check each timetable before you save.</p></div>
            <?php if ($term): ?><div class="term-stamp"><span>ACTIVE TERM</span><strong><?= h($term['school_year'] . ' · ' . $term['semester']) ?></strong></div><?php endif; ?>
        </div>
        <?php if (!$term): ?><section class="empty-panel"><span class="empty-symbol">—</span><div><h2>Enrollment is not open</h2><p>There is no active term to select classes for right now.</p></div></section>
        <?php elseif (!$editable): ?><section class="content-panel submitted-banner"><span class="status-mark">✓</span><div><span class="eyebrow">SUBMITTED ENROLLMENT</span><h2>Class selections are locked</h2><p>Your form is <?= h(statusLabel($enrollment['status'])) ?>. You can still review your selected sections, but submitted enrollments cannot be edited.</p><a class="text-link" href="index.php?page=status">View enrollment status →</a></div></section>
        <?php elseif (!$subjects): ?><section class="empty-panel"><span class="empty-symbol">—</span><div><h2>No sections to choose</h2><p>There are no sections currently offered for <?= h($student['program_code']) ?>, year <?= (int) $student['year_level'] ?>.</p></div></section>
        <?php else: ?>
            <div class="selection-meta"><span><strong><?= $selectedCount ?></strong> section<?= $selectedCount === 1 ? '' : 's' ?> selected</span><span><?= count($subjects) ?> offered subjects · <?= (int) array_sum(array_column($subjects, 'units')) ?> total units</span></div>
            <form method="post" id="enrollment-form">
                <?= csrfField() ?>
                <div class="subject-list">
                <?php foreach ($subjects as $index => $subject): ?>
                    <fieldset class="subject-block">
                        <legend><span class="subject-number"><?= str_pad((string) ($index + 1), 2, '0', STR_PAD_LEFT) ?></span><span class="subject-title"><b><?= h($subject['subject_code']) ?></b><strong><?= h($subject['subject_name']) ?></strong></span><span class="subject-units"><?= (int) $subject['units'] ?> units</span></legend>
                        <div class="section-options">
                        <?php foreach ($subject['sections'] as $section): $remaining = max(0, (int) $section['max_slots'] - (int) $section['occupied_slots']); ?>
                            <label class="section-option <?= $remaining < 1 ? 'section-full' : '' ?>">
                                <input type="radio" name="sections[<?= (int) $subject['subject_id'] ?>]" value="<?= (int) $section['section_id'] ?>" <?= isset($selectedMap[(int) $section['section_id']]) ? 'checked' : '' ?> <?= $remaining < 1 ? 'disabled' : '' ?>>
                                <span class="option-check" aria-hidden="true"></span>
                                <span class="option-main"><strong>Section <?= h($section['section_name']) ?></strong><span><?= h($section['day_pattern']) ?> · <?= h(formatTime($section['start_time']) . '–' . formatTime($section['end_time'])) ?></span></span>
                                <span class="option-location"><?= h($section['room'] ?: 'Room TBA') ?><small><?= h($section['instructor'] ?: 'Instructor TBA') ?></small></span>
                                <span class="slot-count <?= $remaining < 5 ? 'slot-low' : '' ?>"><?= $remaining > 0 ? $remaining . ' seats' : 'Full' ?><small>remaining</small></span>
                            </label>
                        <?php endforeach; ?>
                        </div>
                    </fieldset>
                <?php endforeach; ?>
                </div>
                <div class="enrollment-actions">
                    <p><span class="eyebrow">BEFORE YOU SUBMIT</span><small>Review your timetable and choices. Submission sends your enrollment for registrar review and locks these selections.</small></p>
                    <div class="button-group">
                        <button class="button button-outline" type="submit" name="action" value="save_enrollment">Save draft</button>
                        <button class="button button-primary" type="submit" name="action" value="submit_enrollment" <?= $selectedCount < count($subjects) ? 'data-requires-all="true"' : '' ?>>Submit enrollment <span aria-hidden="true">→</span></button>
                    </div>
                </div>
            </form>
        <?php endif; ?>
    <?php elseif ($page === 'status' && $student): ?>
        <?php $selected = $enrollment ? chosenSections((int) $enrollment['enrollment_id']) : []; ?>
        <div class="page-heading"><div><span class="eyebrow">YOUR ENROLLMENT</span><h1>Where things stand.</h1><p>Keep this page close for your latest enrollment details.</p></div><?php if ($term): ?><div class="term-stamp"><span>ACTIVE TERM</span><strong><?= h($term['school_year'] . ' · ' . $term['semester']) ?></strong></div><?php endif; ?></div>
        <?php if (!$term || !$enrollment): ?><section class="empty-panel"><span class="empty-symbol">01</span><div><h2>No enrollment submitted</h2><p>Start with your class selection. Save a draft anytime before you submit.</p><?php if ($term): ?><a class="button button-primary" href="index.php?page=enrollment">Choose classes <span aria-hidden="true">→</span></a><?php endif; ?></div></section>
        <?php else: ?>
            <?php
            $statusMessage = match ($enrollment['status']) {
                'draft' => 'Your class plan is saved as a draft.',
                'pending' => 'Your submission is waiting for the registrar to review it.',
                'approved' => 'The registrar approved your enrollment. You are not marked fully enrolled until the portal status changes to Enrolled.',
                'enrolled' => 'Your enrollment is confirmed. You are officially marked as enrolled for this term.',
                'rejected' => 'The registrar needs you to review the note below and contact Student Services.',
                default => 'Check back here for updates from the registrar.',
            };
            ?>
            <section class="status-overview"><div><span class="eyebrow">CURRENT STATUS</span><h2><?= h(statusLabel($enrollment['status'])) ?></h2><p><?= h($statusMessage) ?><?= $enrollment['submitted_at'] ? ' Submitted ' . h(date('F j, Y \a\t g:i A', strtotime($enrollment['submitted_at']))) . '.' : '' ?></p></div><span class="status-seal"><?= $enrollment['status'] === 'enrolled' ? '✓' : 'N' ?></span></section>
            <?php if ($enrollment['remarks']): ?><section class="content-panel remark-panel"><span class="eyebrow">REGISTRAR NOTE</span><p><?= h($enrollment['remarks']) ?></p><?php if ($enrollment['appointment_at']): ?><small>Appointment: <?= h(date('M j, Y · g:i A', strtotime($enrollment['appointment_at']))) ?></small><?php endif; ?></section><?php endif; ?>
            <section class="content-panel status-classes"><div class="panel-heading"><div><span class="eyebrow"><?= count($selected) ?> CLASS<?= count($selected) === 1 ? '' : 'ES' ?></span><h2>Selected sections</h2></div><?php if ($enrollment['status'] === 'draft'): ?><a class="text-link" href="index.php?page=enrollment">Continue editing →</a><?php endif; ?></div>
                <?php if ($selected): ?><div class="class-list"><?php foreach ($selected as $section): ?><div class="class-row"><div class="class-code"><?= h($section['subject_code']) ?></div><div class="class-details"><strong><?= h($section['subject_name']) ?></strong><span><?= h($section['day_pattern']) ?> · <?= h(formatTime($section['start_time']) . '–' . formatTime($section['end_time'])) ?> · <?= h($section['section_name']) ?></span><small><?= h(($section['room'] ?: 'Room TBA') . ' · ' . ($section['instructor'] ?: 'Instructor TBA')) ?></small></div><span class="units"><?= (int) $section['units'] ?> u</span></div><?php endforeach; ?></div><?php else: ?><p class="muted">No sections are attached to this enrollment yet.</p><?php endif; ?>
            </section>
            <?php if (in_array($enrollment['status'], ['pending', 'approved', 'enrolled'], true)): ?><div class="inline-action"><div><span class="eyebrow">PAYMENT FOLLOW-UP</span><strong>Have payment details to share?</strong><small>Record a method, amount, and reference for the cashier to review.</small></div><a class="button button-outline" href="index.php?page=payments">Add payment details <span aria-hidden="true">→</span></a></div><?php endif; ?>
        <?php endif; ?>
    <?php elseif ($page === 'payments' && $student): ?>
        <?php
        $paymentRows = [];
        $canPay = $enrollment && in_array($enrollment['status'], ['pending', 'approved', 'enrolled'], true);
        if ($enrollment) {
            $paymentStatement = db()->prepare(
                'SELECT amount, method, reference_no, status, paid_at
                 FROM payments WHERE enrollment_id = :enrollment_id ORDER BY paid_at DESC, payment_id DESC'
            );
            $paymentStatement->execute(['enrollment_id' => (int) $enrollment['enrollment_id']]);
            $paymentRows = $paymentStatement->fetchAll();
        }
        ?>
        <div class="page-heading"><div><span class="eyebrow">PAYMENT FOLLOW-UP</span><h1>Record payment details.</h1><p>Share what you’ve paid so the cashier can review and match it to your enrollment.</p></div></div>
        <div class="payment-disclaimer"><span class="disclaimer-icon">i</span><p><strong>This portal does not process payments.</strong> Submitting this form only records your details as pending for staff follow-up. Do not enter card numbers or account passwords.</p></div>
        <?php if ($canPay): ?>
            <section class="content-panel payment-form-panel"><span class="eyebrow">NEW PAYMENT RECORD</span><h2>What should the cashier know?</h2><form method="post" class="form-grid payment-form">
                <?= csrfField() ?><input type="hidden" name="action" value="submit_payment">
                <label>Amount paid (₱)<input type="number" name="amount" min="0.01" max="99999999.99" step="0.01" placeholder="0.00" required></label>
                <label>Payment method<select name="method" required><option value="">Choose…</option><option value="gcash">GCash</option><option value="maya">Maya</option><option value="bank">Bank transfer</option><option value="cash">Cash</option></select></label>
                <label class="span-2">Reference number <span class="optional">Optional</span><input name="reference_no" maxlength="60" placeholder="For example, transaction or receipt reference"></label>
                <div class="span-2 payment-actions"><small>Records are marked pending until reviewed by the cashier.</small><button class="button button-primary" type="submit">Submit for review <span aria-hidden="true">→</span></button></div>
            </form></section>
        <?php elseif (!$enrollment): ?><section class="empty-panel"><span class="empty-symbol">₱</span><div><h2>Enrollment comes first</h2><p>Submit your class selections to open a payment record for this term.</p><a class="button button-primary" href="index.php?page=enrollment">Choose classes <span aria-hidden="true">→</span></a></div></section>
        <?php else: ?><section class="empty-panel"><span class="empty-symbol">₱</span><div><h2>Payment details are not available yet</h2><p>Your enrollment must be pending, approved, or enrolled before you can record payment details.</p><a class="text-link" href="index.php?page=status">Review enrollment status →</a></div></section><?php endif; ?>
        <section class="content-panel payment-history"><div class="panel-heading"><div><span class="eyebrow">YOUR RECORDS</span><h2>Payment history</h2></div></div>
            <?php if ($paymentRows): ?><div class="table-scroll"><table><thead><tr><th>Date submitted</th><th>Method</th><th>Reference</th><th>Status</th><th class="amount-cell">Amount</th></tr></thead><tbody><?php foreach ($paymentRows as $payment): ?><tr><td><?= h(date('M j, Y', strtotime($payment['paid_at']))) ?></td><td><?= h(strtoupper($payment['method'])) ?></td><td><?= h($payment['reference_no'] ?: '—') ?></td><td><span class="status-pill status-<?= h($payment['status']) ?>"><?= h(ucfirst($payment['status'])) ?></span></td><td class="amount-cell">₱<?= h(number_format((float) $payment['amount'], 2)) ?></td></tr><?php endforeach; ?></tbody></table></div><?php else: ?><div class="empty-inline"><span>₱</span><p>No payment details recorded yet.</p></div><?php endif; ?>
        </section>
    <?php elseif ($page === 'profile' && $student): ?>
        <div class="page-heading"><div><span class="eyebrow">YOUR DETAILS</span><h1>A little about you.</h1><p>Keep your student information up to date so the right people can reach you.</p></div><div class="profile-initials"><?= h(strtoupper(substr($student['first_name'], 0, 1) . substr($student['last_name'], 0, 1))) ?></div></div>
        <section class="content-panel profile-card"><div class="profile-account"><span class="eyebrow">ACCOUNT EMAIL</span><strong><?= h($student['email']) ?></strong><small>Email changes are managed by student services.</small></div><form method="post" class="profile-form inside">
            <?= csrfField() ?><input type="hidden" name="action" value="save_profile">
            <fieldset><legend>Student details</legend><div class="form-grid">
                <label>First name<input name="first_name" maxlength="60" value="<?= h($student['first_name']) ?>" required></label>
                <label>Middle name<input name="middle_name" maxlength="60" value="<?= h($student['middle_name']) ?>"></label>
                <label>Last name<input name="last_name" maxlength="60" value="<?= h($student['last_name']) ?>" required></label>
                <label>Date of birth<input type="date" name="birthdate" value="<?= h($student['birthdate']) ?>" required></label>
                <label>Sex<select name="sex" required><option value="F" <?= $student['sex'] === 'F' ? 'selected' : '' ?>>Female</option><option value="M" <?= $student['sex'] === 'M' ? 'selected' : '' ?>>Male</option></select></label>
                <label>Program<input value="<?= h($student['program_code'] . ' — ' . $student['program_name']) ?>" disabled></label>
                <label>Year level<input value="Year <?= (int) $student['year_level'] ?>" disabled></label>
                <label>Contact number<input name="contact_no" maxlength="20" value="<?= h($student['contact_no']) ?>"></label>
                <label class="span-2">Home address<input name="address" maxlength="255" value="<?= h($student['address']) ?>"></label>
            </div></fieldset>
            <fieldset><legend>Guardian contact <span class="optional">Optional</span></legend><div class="form-grid">
                <label>Guardian name<input name="guardian_name" maxlength="120" value="<?= h($student['guardian_name']) ?>"></label>
                <label>Guardian contact number<input name="guardian_no" maxlength="20" value="<?= h($student['guardian_no']) ?>"></label>
            </div></fieldset>
            <div class="form-actions"><span class="muted">Your changes are saved securely to your student profile.</span><button class="button button-primary" type="submit">Save changes <span aria-hidden="true">→</span></button></div>
        </form></section>
    <?php endif; ?>
</main>
<footer class="<?= $student ? 'site-footer' : 'auth-footer' ?>">
    <span>Northfield College <b>·</b> Student Services</span><span>Questions? Visit the registrar during office hours.</span>
</footer>
<script>
document.querySelectorAll('[data-requires-all]').forEach((button) => {
    button.addEventListener('click', (event) => {
        const form = button.form;
        const groups = new Set(Array.from(form.querySelectorAll('input[type="radio"]')).map((input) => input.name));
        const chosen = new Set(Array.from(form.querySelectorAll('input[type="radio"]:checked')).map((input) => input.name));
        if (groups.size !== chosen.size) {
            event.preventDefault();
            window.alert('Choose one available section for every subject before submitting.');
        }
    });
});
</script>
</body>
</html>
