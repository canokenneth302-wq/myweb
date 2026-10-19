# Northfield Student Enrollment Portal

A PHP portal backed by the existing `enrollment_db` MySQL database. Students can register, sign in, select classes, submit enrollment, and track whether their record is pending, approved, or fully enrolled. Registrar/admin staff can review submissions in a separate protected queue, approve them, and mark approved records as enrolled. Approval sends an SMS through Semaphore when configured.

## Run locally

1. Place this folder under `C:\xampp2\htdocs\online-enrollment`.
2. Start Apache and MySQL in XAMPP.
3. Visit `http://localhost/online-enrollment/`.
4. Use the existing `enrollment_db` schema. The application does not create, migrate, seed, or clean database objects or records.
5. Student status page: `http://localhost/online-enrollment/index.php?page=status`.
6. Registrar review queue: `http://localhost/online-enrollment/registrar.php`.

Database settings are in `config.php`. Defaults match the local XAMPP setup. Override with environment variables `ENROLLMENT_DB_HOST`, `ENROLLMENT_DB_NAME`, `ENROLLMENT_DB_USER`, and `ENROLLMENT_DB_PASSWORD` when needed; do not commit real credentials.

## Create a registrar account

Registrar accounts are not publicly self-registerable. Generate a password hash with the local PHP CLI, replacing the example password with a new strong password:

```powershell
& 'C:\xampp\php\php.exe' -r "echo password_hash('REPLACE_WITH_A_LONG_PASSWORD', PASSWORD_DEFAULT), PHP_EOL;"
```

In phpMyAdmin, add an authorized account using the generated hash:

```sql
INSERT INTO users (email, password_hash, role)
VALUES ('registrar@example.edu', 'PASTE_THE_GENERATED_HASH_HERE', 'registrar');
```

Keep the password private and do not save the hash or password in the project. Admin accounts with the existing `admin` role can also use the registrar queue.

## Configure Semaphore SMS

1. Create a Semaphore account, obtain an API key, and make sure it has SMS credits. SMS provider charges may apply.
2. Set `SEMAPHORE_API_KEY` in the Apache environment (for example, in XAMPP's Apache `httpd.conf`):

   ```apache
   SetEnv SEMAPHORE_API_KEY "your-private-api-key"
   ```

3. Optionally set `SEMAPHORE_SENDER_NAME` if your Semaphore account has an approved sender name:

   ```apache
   SetEnv SEMAPHORE_SENDER_NAME "YourSenderName"
   ```

4. Restart Apache. Never put the API key in a public HTML file, JavaScript, or a committed config file.

When a registrar approves a pending record, the portal commits the status and creates an in-portal notification, then requests an SMS to the student's Philippine mobile number. Supported phone formats include `09XXXXXXXXX` and `+639XXXXXXXXX`. If SMS is not configured or the provider request fails, the enrollment remains approved and the registrar can use **Resend SMS** after fixing the settings.

## Notes

- New accounts are student-role records only. Only registrar/admin accounts can access the staff review queue.
- `pending` means awaiting review, `approved` means accepted by the registrar, and `enrolled` means the registrar has completed enrollment. Students can see the current status on their status page and dashboard.
- Approving does not automatically mark a student fully enrolled. The registrar uses **Mark enrolled** only after the college's enrollment process is complete.
- Submitted enrollment choices are locked. Available seats are rechecked while submission is saved; drafts do not reserve a seat.
- Payment forms only record amount, method, and an optional reference number as pending. They do not move money.
- Student actions are scoped to the signed-in student's own records. Forms use session CSRF tokens, parameterized PDO queries, password hashing, and escaped output.
