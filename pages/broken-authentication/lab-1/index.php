<?php
$page_title = "Broken Authentication Lab 1 - Weak Password Policy";
require_once '../../../config/env.php';
require_once '../../../template/header.php';

$message = '';
$attempts = $_SESSION['login_attempts'] ?? 0;
$alert_class = "alert-danger";
$error_message = '';
$is_login = false;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if($_SESSION['login_attempts'] > 5){
        $error_message = "Akun anda terblokir, sudah lebih dari 5 percobaan password";
        $alert_class = "alert-danger";
    }
    if($error_message == ''){
        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error_message = "Invalid email format";
        }
        if($error_message == ''){
            $_SESSION['login_attempts'] = $attempts + 1;
        
            $query = "SELECT * FROM users WHERE email = :email AND password = :password";
        
            try {
                $result = $pdo->prepare($query);
                $result->bindParam('email', $email);
                $result->bindParam('password', sha1($password));
                $result->execute();
                if ($result && $result->rowCount() > 0) {
                    // print_r($result);
                    // $user = $result->fetch(PDO::FETCH_ASSOC);
                    $message = "Login successful! Weak password detected: " . htmlspecialchars($password);
                    $alert_class = "alert-info";
                    $is_login = true;
                    $_SESSION['login_attempts'] = 0;
                } else {
                    $_SESSION['login_attempts'] = ($_SESSION['login_attempts'] ?? 0) + 1;
                    $message = "Invalid credentials. Attempt #" . $_SESSION['login_attempts'];
                }
            } catch (PDOException $e) {
                $error_message = "Database error: " . $e->getMessage();
                $alert_class = "alert-danger";
            }
        }
    }
}
?>

<div class="container-fluid">
    <div class="row">
        <div class="col-md-3 col-lg-2 px-0">
            <?php include '../../../template/nav.php'; ?>
        </div>
        
        <div class="col-md-9 col-lg-10 mt-60">
            <div class="container-fluid py-4">
                <div class="row">
                    <div class="col-12">
                        <nav aria-label="breadcrumb">
                            <ol class="breadcrumb">
                                <li class="breadcrumb-item"><a href="<?php echo BASE_URL; ?>">Dashboard</a></li>
                                <li class="breadcrumb-item"><a href="../">Broken Authentication</a></li>
                                <li class="breadcrumb-item active">Lab 1</li>
                            </ol>
                        </nav>
                        
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h1 class="h2">Lab 1: Weak Password Policy</h1>
                            <span class="lab-difficulty difficulty-easy">Easy</span>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-8">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">Login System</h5>
                            </div>
                            <div class="card-body">
                                <?php if ($message): ?>
                                    <div class="alert <?php echo $alert_class;?>" role="alert">
                                        <?php echo $message; ?>
                                    </div>
                                <?php endif; ?>
                                <?php if ($error_message): ?>
                                    <div class="alert <?php echo $alert_class;?>" role="alert">
                                        <?php echo $error_message; ?>
                                    </div>
                                <?php endif; ?>
                                <?php if(!$is_login): ?>
                                <form method="post">
                                    <div class="mb-3">
                                        <label for="email" class="form-label">email:</label>
                                        <input type="text" class="form-control" id="email" name="email" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="password" class="form-label">Password:</label>
                                        <input type="password" class="form-control" id="password" name="password" required>
                                    </div>
                                    
                                    <button type="submit" class="btn btn-primary">Login</button>
                                </form>
                                <?php endif; ?>
                                <div class="mt-3">
                                    <small class="text-muted">Login attempts: <?php echo $attempts; ?></small>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">💡 Lab Objectives</h5>
                            </div>
                            <div class="card-body">
                                <ul class="list-unstyled">
                                    <li>✅ Exploit weak passwords</li>
                                    <li>✅ Perform brute force attack</li>
                                    <li>✅ No rate limiting bypass</li>
                                </ul>
                            </div>
                        </div>
                        
                        <div class="card mt-3">
                            <div class="card-header">
                                <h5 class="mb-0">🛠️ Common Passwords</h5>
                            </div>
                            <div class="card-body">
                                <div class="accordion" id="passwordsAccordion">
                                    <div class="accordion-item">
                                        <h2 class="accordion-header">
                                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#weak">
                                                Weak Passwords
                                            </button>
                                        </h2>
                                        <div id="weak" class="accordion-collapse collapse" data-bs-parent="#passwordsAccordion">
                                            <div class="accordion-body">
                                                Try: 123456, password, admin, test, 12345
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once '../../../template/footer.php'; ?>