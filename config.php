<?php
declare(strict_types=1);

return [
    'db_host' => getenv('ENROLLMENT_DB_HOST') ?: '127.0.0.1',
    'db_name' => getenv('ENROLLMENT_DB_NAME') ?: 'enrollment_db',
    'db_user' => getenv('ENROLLMENT_DB_USER') ?: 'root',
    'db_password' => getenv('ENROLLMENT_DB_PASSWORD') ?: '',
    'semaphore_api_key' => getenv('SEMAPHORE_API_KEY') ?: '',
    'semaphore_sender_name' => getenv('SEMAPHORE_SENDER_NAME') ?: '',
];
