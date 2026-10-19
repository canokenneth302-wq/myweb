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

function currentRegistrar(): ?array
{
    if (empty($_SESSION['registrar_user_id'])) {
        return null;
    }
    $statement = db()->prepare(
        'SELECT user_id, email, role FROM users
         WHERE user_id = :user_id AND role IN ("registrar", "admin") LIMIT 1'
    );
    $statement->execute(['user_id' => (int) $_SESSION['registrar_user_id']]);
    $user = $statement->fetch();
    if (!$user) {
        unset($_SESSION['registrar_user_id']);
        return null;
    }
    return $user;
}

function enrollmentForSms(int $enrollmentId): array
{
    $statement = db()->prepare(
        'SELECT e.enrollment_id, e.status, s.first_name, s.contact_no,
                t.school_year, t.semester
         FROM enrollments e
         JOIN students s ON s.student_id = e.student_id
         JOIN terms t ON t.term_id = e.term_id
         WHERE e.enrollment_id = :enrollment_id LIMIT 1'
    );
    $statement->execute(['enrollment_id' => $enrollmentId]);
    $enrollment = $statement->fetch();
    if (!$enrollment) {
        throw new DomainException('Enrollment record not found.');
    }
    if ($enrollment['contact_no'] === null || trim((string) $enrollment['contact_no']) === '') {
        throw new DomainException('The student has no contact number. Update the student profile before sending SMS.');
    }
    return $enrollment;
}

function sendApprovalSms(array $enrollment): void
{
    $message = sprintf(
        'Hi %s, your enrollment for SY %s %s has been approved by the Registrar. Please sign in to your student portal for details.',
        $enrollment['first_name'],
        $enrollment['school_year'],
        $enrollment['semester']
    );
    sendSemaphoreSms((string) $enrollment['contact_no'], $message);
}

$error = '';
$flash = takeFlash();
$registrar = null;
$enrollments = [];
$sectionMap = [];

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
            if (!$user || !in_array($user['role'], ['registrar', 'admin'], true)
                || !password_verify($password, $user['password_hash'])) {
                throw new DomainException('Sign-in failed. Use an authorized registrar account.');
            }
            session_regenerate_id(true);
            $_SESSION['registrar_user_id'] = (int) $user['user_id'];
            unset($_SESSION['csrf_token']);
            setFlash('success', 'You are signed in to the registrar review queue.');
            header('Location: registrar.php');
            exit;
        }

        if ($action === 'logout') {
            unset($_SESSION['registrar_user_id']);
            session_regenerate_id(true);
            header('Location: registrar.php');
            exit;
        }

        $registrar = currentRegistrar();
        if ($registrar === null) {
            throw new DomainException('Sign in with an authorized registrar account to continue.');
        }
        $enrollmentId = filter_var($_POST['enrollment_id'] ?? null, FILTER_VALIDATE_INT);
        if (!$enrollmentId || $enrollmentId < 1) {
            throw new DomainException('Choose a valid enrollment record.');
        }

        if ($action === 'approve') {
            $pdo = db();
            $pdo->beginTransaction();
            try {
                $lock = $pdo->prepare(
                    'SELECT e.enrollment_id, e.status, e.student_id, s.user_id
                     FROM enrollments e
                     JOIN students s ON s.student_id = e.student_id
                     WHERE e.enrollment_id = :enrollment_id FOR UPDATE'
                );
                $lock->execute(['enrollment_id' => $enrollmentId]);
                $record = $lock->fetch();
                if (!$record || $record['status'] !== 'pending') {
                    throw new DomainException('Only pending enrollments can be approved. Refresh the queue and try again.');
                }
                $update = $pdo->prepare(
                    'UPDATE enrollments
                     SET status = "approved", reviewed_by = :reviewed_by
                     WHERE enrollment_id = :enrollment_id AND status = "pending"'
                );
                $update->execute([
                    'reviewed_by' => (int) $registrar['user_id'],
                    'enrollment_id' => $enrollmentId,
                ]);
                if ($update->rowCount() !== 1) {
                    throw new DomainException('This enrollment was updated by another staff member. Refresh the queue.');
                }
                $notice = $pdo->prepare(
                    'INSERT INTO notifications (user_id, message)
                     VALUES (:user_id, :message)'
                );
                $notice->execute([
                    'user_id' => (int) $record['user_id'],
                    'message' => 'Your enrollment was approved by the Registrar. Sign in to view your enrollment status.',
                ]);
                $pdo->commit();
            } catch (Throwable $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                throw $exception;
            }

            try {
                sendApprovalSms(enrollmentForSms($enrollmentId));
                setFlash('success', 'Enrollment approved and approval SMS accepted by Semaphore.');
            } catch (DomainException $exception) {
                setFlash('error', $exception->getMessage());
            } catch (Throwable $exception) {
                error_log('Approval SMS error: ' . $exception->getMessage());
                setFlash('error', 'Enrollment approved, but the SMS could not be sent. Check the server log and SMS settings, then retry.');
            }
            header('Location: registrar.php');
            exit;
        }

        if ($action === 'resend_sms') {
            $enrollment = enrollmentForSms($enrollmentId);
            if ($enrollment['status'] !== 'approved') {
                throw new DomainException('SMS can only be resent for an approved enrollment.');
            }
            sendApprovalSms($enrollment);
            setFlash('success', 'Approval SMS accepted by Semaphore.');
            header('Location: registrar.php');
            exit;
        }

        if ($action === 'mark_enrolled') {
            $pdo = db();
            $pdo->beginTransaction();
            try {
                $update = $pdo->prepare(
                    'UPDATE enrollments
                     SET status = "enrolled"
                     WHERE enrollment_id = :enrollment_id AND status = "approved"'
                );
                $update->execute(['enrollment_id' => $enrollmentId]);
                if ($update->rowCount() !== 1) {
                    throw new DomainException('Only approved enrollments can be marked enrolled. Refresh the queue and try again.');
                }
                $notice = $pdo->prepare(
                    'INSERT INTO notifications (user_id, message)
                     SELECT s.user_id, :message
                     FROM enrollments e JOIN students s ON s.student_id = e.student_id
                     WHERE e.enrollment_id = :enrollment_id'
                );
                $notice->execute([
                    'message' => 'The Registrar marked your enrollment as enrolled. Check your student portal for details.',
                    'enrollment_id' => $enrollmentId,
                ]);
                $pdo->commit();
            } catch (Throwable $exception) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                throw $exception;
            }
            setFlash('success', 'Student status updated to Enrolled.');
            header('Location: registrar.php');
            exit;
        }

        throw new DomainException('That registrar action is not available.');
    }

    $registrar = currentRegistrar();
    if ($registrar !== null) {
        $statement = db()->query(
            'SELECT e.enrollment_id, e.status, e.submitted_at,
                    s.student_no, s.first_name, s.last_name, s.contact_no,
                    p.program_code, t.school_year, t.semester
             FROM enrollments e
             JOIN students s ON s.student_id = e.student_id
             JOIN programs p ON p.program_id = s.program_id
             JOIN terms t ON t.term_id = e.term_id
             WHERE e.status IN ("pending", "approved")
             ORDER BY FIELD(e.status, "pending", "approved"), e.submitted_at, e.enrollment_id'
        );
        $enrollments = $statement->fetchAll();
        if ($enrollments !== []) {
            $ids = array_map(static fn(array $row): int => (int) $row['enrollment_id'], $enrollments);
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $classes = db()->prepare(
                'SELECT ei.enrollment_id, sub.subject_code, sec.section_name
                 FROM enrollment_items ei
                 JOIN sections sec ON sec.section_id = ei.section_id
                 JOIN subjects sub ON sub.subject_id = sec.subject_id
                 WHERE ei.enrollment_id IN (' . $placeholders . ')
                 ORDER BY sub.subject_code'
            );
            $classes->execute($ids);
            foreach ($classes->fetchAll() as $class) {
                $sectionMap[(int) $class['enrollment_id']][] =
                    $class['subject_code'] . ' · Section ' . $class['section_name'];
            }
        }
    }
} catch (DomainException $exception) {
    $error = $exception->getMessage();
} catch (PDOException $exception) {
    error_log('Registrar portal database error: ' . $exception->getMessage());
    $error = 'We could not complete that request right now. Please try again.';
} catch (Throwable $exception) {
    error_log('Registrar portal error: ' . $exception->getMessage());
    $error = 'Something unexpected happened. Please try again.';
}

?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#17392f">
    <title>Registrar review · Northfield Student Portal</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body class="registrar-page">
<header class="registrar-topbar">
    <a class="brand brand-dark" href="registrar.php">
        <span class="brand-mark" aria-hidden="true">N</span>
        <span><strong>Northfield</strong><small>REGISTRAR REVIEW</small></span>
    </a>
    <?php if ($registrar): ?>
        <div class="registrar-account">
            <span><?= h($registrar['email']) ?> · <?= h(ucfirst($registrar['role'])) ?></span>
            <form method="post">
                <?= csrfField() ?>
                <input type="hidden" name="action" value="logout">
                <button class="signout" type="submit">Sign out</button>
            </form>
        </div>
    <?php endif; ?>
</header>
<main class="registrar-main">
    <?php if ($flash): ?>
        <div class="notice notice-<?= h($flash['type']) ?>" role="status"><?= h($flash['message']) ?></div>
    <?php endif; ?>
    <?php if ($error !== ''): ?>
        <div class="notice notice-error" role="alert"><?= h($error) ?></div>
    <?php endif; ?>

    <?php if (!$registrar): ?>
        <section class="registrar-login">
            <span class="eyebrow">STAFF ACCESS</span>
            <h1>Registrar review</h1>
            <p class="muted">Sign in using an authorized registrar or admin account.</p>
            <form method="post" class="form-stack">
                <?= csrfField() ?>
                <input type="hidden" name="action" value="login">
                <label>Email address<input type="email" name="email" maxlength="120" autocomplete="username" required></label>
                <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
                <button class="button button-primary button-wide" type="submit">Sign in to review</button>
            </form>
            <p class="tiny-note">Student accounts cannot access this page.</p>
        </section>
    <?php else: ?>
        <div class="page-heading">
            <div><span class="eyebrow">STUDENT ENROLLMENTS</span><h1>Registrar review queue.</h1><p>Approve pending submissions or mark approved students as enrolled.</p></div>
            <div class="term-stamp"><span>NEEDS REVIEW</span><strong><?= count(array_filter($enrollments, static fn(array $row): bool => $row['status'] === 'pending')) ?></strong></div>
        </div>
        <div class="payment-disclaimer">
            <span class="disclaimer-icon">i</span>
            <p><strong>Approval and enrollment are separate steps.</strong> Approving changes the student status to Approved and sends an SMS through Semaphore. Mark the student Enrolled only after registration is complete. If SMS settings are missing or delivery fails, the approval remains saved and you can retry the SMS.</p>
        </div>
        <?php if ($enrollments === []): ?>
            <section class="empty-panel"><span class="empty-symbol">✓</span><div><h2>Queue is clear</h2><p>There are no pending approvals or approved enrollments waiting to be marked enrolled.</p></div></section>
        <?php else: ?>
            <section class="content-panel registrar-queue">
                <div class="table-scroll">
                    <table class="registrar-table">
                        <thead><tr><th>Student</th><th>Program / term</th><th>Classes</th><th>Status</th><th>Actions</th></tr></thead>
                        <tbody>
                        <?php foreach ($enrollments as $row): ?>
                            <tr>
                                <td>
                                    <strong><?= h($row['first_name'] . ' ' . $row['last_name']) ?></strong>
                                    <small><?= h($row['student_no'] ?: 'No student number') ?> · <?= h($row['contact_no'] ?: 'No mobile number') ?></small>
                                    <small>Submitted <?= $row['submitted_at'] ? h(date('M j, Y g:i A', strtotime($row['submitted_at']))) : '—' ?></small>
                                </td>
                                <td><?= h($row['program_code']) ?><small><?= h($row['school_year'] . ' · ' . $row['semester']) ?></small></td>
                                <td><?= h(implode(', ', $sectionMap[(int) $row['enrollment_id']] ?? [])) ?></td>
                                <td><span class="status-pill status-<?= h($row['status']) ?>"><?= h(statusLabel($row['status'])) ?></span></td>
                                <td>
                                    <div class="registrar-actions">
                                        <?php if ($row['status'] === 'pending'): ?>
                                            <form method="post" onsubmit="return confirm('Approve this enrollment and send an SMS to the student?');">
                                                <?= csrfField() ?>
                                                <input type="hidden" name="action" value="approve">
                                                <input type="hidden" name="enrollment_id" value="<?= (int) $row['enrollment_id'] ?>">
                                                <button class="button button-primary" type="submit">Approve + SMS</button>
                                            </form>
                                        <?php else: ?>
                                            <form method="post">
                                                <?= csrfField() ?>
                                                <input type="hidden" name="action" value="resend_sms">
                                                <input type="hidden" name="enrollment_id" value="<?= (int) $row['enrollment_id'] ?>">
                                                <button class="button button-outline" type="submit">Resend SMS</button>
                                            </form>
                                            <form method="post" onsubmit="return confirm('Mark this student as fully enrolled?');">
                                                <?= csrfField() ?>
                                                <input type="hidden" name="action" value="mark_enrolled">
                                                <input type="hidden" name="enrollment_id" value="<?= (int) $row['enrollment_id'] ?>">
                                                <button class="button button-primary" type="submit">Mark enrolled</button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </section>
        <?php endif; ?>
    <?php endif; ?>
</main>
</body>
</html>
