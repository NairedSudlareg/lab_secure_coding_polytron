<?php
// Start session if not already started
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Database Configuration for docker
define('DB_HOST', 'secure_coding_polytron');
define('DB_PORT', '3306');
define('DB_NAME', 'db_secure_coding_polytron');
define('DB_USER', 'root');
define('DB_PASS', 'root');

#define('DB_HOST', 'localhost');
#define('DB_PORT', '3306');
#define('DB_NAME', 'db_secure_coding');
#define('DB_USER', 'root');
#define('DB_PASS', 'root');

// Base URL Configuration
define('BASE_URL', 'http://localhost:8001');

define('SITE_NAME', 'Cybersecurity Learning Platform - Polytron');

// Security Configuration
define('SESSION_TIMEOUT', 3600); // 1 hour
define('MAX_LOGIN_ATTEMPTS', 5);

// Database Connection
try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_NAME, DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    // In a real application, log this error instead of displaying it
    error_log("Database connection failed: " . $e->getMessage());
    die("Database connection failed. Please check your configuration.");
}
