<?php
$page_title = "Sensitive Data Exposure Lab 1 - Unencrypted Storage";
require_once '../../../config/env.php';
require_once '../../../template/header.php';


$message = '';
$show_data = false;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "Invalid email format";
    }

    if($message == ''){
        // VULNERABLE - Plain text password storage simulation
        $users_data = [
            'admin' => password_hash('admin123', PASSWORD_DEFAULT),
            'user1' => password_hash('password123', PASSWORD_DEFAULT),
            'user2' => password_hash('mypassword', PASSWORD_DEFAULT),
            'john' => password_hash('john2023', PASSWORD_DEFAULT)
        ];
    
        // if (isset($users_data[$email]) && $users_data[$email] === $password) {
        if (isset($users_data[$email]) && password_verify($password, $users_data[$email])) {
            $message = "Login successful!";
            $show_data = true;
        } else {
            $message = "Invalid credentials.";
        }
    }

}
?>
<script src="login.js"></script>
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
                                <li class="breadcrumb-item"><a href="../">Sensitive Data Exposure</a></li>
                                <li class="breadcrumb-item active">Lab 1</li>
                            </ol>
                        </nav>

                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h1 class="h2">Lab 1: Sensitive File Exposure</h1>
                            <span class="lab-difficulty difficulty-easy">Easy</span>
                        </div>
                    </div>
                </div>

                <div class="row">
                    <div class="col-md-8">
                        <div class="card mb-4">
                            <div class="card-header">
                                <h5 class="mb-0">User Login</h5>
                            </div>
                            <div class="card-body">
                                <?php if ($message): ?>
                                    <div class="alert alert-info" role="alert">
                                        <?php echo $message; ?>
                                    </div>
                                <?php endif; ?>

                                <form method="post">
                                    <div class="mb-3">
                                        <label for="email" class="form-label">Email:</label>
                                        <input type="text" class="form-control" id="email" name="email" required>
                                    </div>

                                    <div class="mb-3">
                                        <label for="password" class="form-label">Password:</label>
                                        <input type="password" class="form-control" id="password" name="password" required>
                                    </div>

                                    <button type="submit" class="btn btn-primary">Login</button>
                                </form>
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
                                    <li>✅ Access the .env file via a direct URL</li>
                                    <li>✅ Extract sensitive information such as passwords, tokens, or database credentials</li>
                                    <li>✅ Understand the risks of storing unencrypted configuration files in publicly accessible locations</li>
                                </ul>
                            </div>
                        </div>

                        <div class="card mt-3">
                            <div class="card-header">
                                <h5 class="mb-0">🛠️ Test File Sensitives</h5>
                            </div>
                            <div class="card-body">
                                <div class="accordion" id="credentialsAccordion">
                                    <div class="accordion-item">
                                        <h2 class="accordion-header">
                                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#creds">
                                                File Sensitives
                                            </button>
                                        </h2>
                                        <div id="creds" class="accordion-collapse collapse" data-bs-parent="#credentialsAccordion">
                                            <div class="accordion-body">
                                                /.env <br>
                                                /.log <br>
                                                /login.js
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