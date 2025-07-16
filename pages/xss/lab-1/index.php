<?php
$page_title = "XSS Lab 1 - Stored XSS";
require_once '../../../config/env.php';
require_once '../../../template/header.php';

$message = '';
$profiles = [];
$userID = 0;

// Fetch existing profiles
try {
    $result = $pdo->query("SELECT * FROM user_profiles where user_id = :id");
    $result->bindParam('id', $userID);
    $result->execute();
    $profiles = $result->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    // Table might not exist, create it
    $pdo->exec("CREATE TABLE IF NOT EXISTS user_profiles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        bio TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $name = $_POST['name'] ?? '';
    $bio = $_POST['bio'] ?? '';
    if (!preg_match("/^[a-zA-Z-' ]*$/",$name)) {
        $message = "Invalid input name";
    }
    if($message == ''){
        if(preg_match('/[#$%^&*+\[\]\';\/{}|<>?~\\\\]/', $bio)){
            $message = "Invalid input bio, only alphabet and numeric input";
        }
    }
    if($message == ''){
        $dataExist = 0;
        $query = "SELECT user_id FROM user_profiles WHERE name = :name";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam('name', $name);
        $stmt->execute();
        if ($stmt && $stmt->rowCount() > 0) {
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            $userID = $user['user_id'];
            $dataExist = 1;
        }
        if($userID == 0){
            $query = "SELECT MAX(user_id) as user_id FROM user_profiles";
            $stmt = $pdo->prepare($query);
            $stmt->execute();
            if ($stmt && $stmt->rowCount() > 0) {
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                $userID = $user['user_id'];
            }
        }
        $id = 0;
        $query = "SELECT MAX(id) as id FROM user_profiles";
        $stmt = $pdo->prepare($query);
        $stmt->execute();
        if ($stmt && $stmt->rowCount() > 0) {
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            $id = $user['id'];
        }
        if(!$dataExist){
            $userID+=1;
            $id+=1;
            // VULNERABLE CODE - No XSS protection
            $query = "INSERT INTO user_profiles (id, user_id, name, bio, nik) VALUES (:id,:user_id,:name,:bio,:nik)";
            $stmt = $pdo->prepare($query);
            $stmt->bindParam('id', $id);
            $stmt->bindParam('user_id', $userID);
            $stmt->bindParam('name', $name);
            $stmt->bindParam('bio', $bio);
            $stmt->bindParam('nik', rand(10009,99999));
            if ($stmt->execute()) {
                $message = "Profile create successfully!";
                // Refresh profiles
                $result = $pdo->query("SELECT * FROM user_profiles where user_id = $userID");
                $profiles = $result->fetchAll(PDO::FETCH_ASSOC);
            } else {
                $message = "Error inserting profile.";
            }
        }else{
            // VULNERABLE CODE - No XSS protection
            $query = "UPDATE user_profiles SET name = :name, bio = :bio where user_id = :id";
            $stmt = $pdo->prepare($query);
            $stmt->bindParam('id', $userID);
            $stmt->bindParam('name', $name);
            $stmt->bindParam('bio', $bio);
            
            if ($stmt->execute()) {
                $message = "Profile updated successfully!";
                // Refresh profiles
                $result = $pdo->query("SELECT * FROM user_profiles where user_id = $userID");
                $profiles = $result->fetchAll(PDO::FETCH_ASSOC);
            } else {
                $message = "Error updating profile.";
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
                                <li class="breadcrumb-item"><a href="../">XSS</a></li>
                                <li class="breadcrumb-item active">Lab 1</li>
                            </ol>
                        </nav>
                        
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h1 class="h2">Lab 1: Stored XSS via Profile Update</h1>
                            <span class="lab-difficulty difficulty-medium">Medium</span>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-8">
                        <div class="card mb-4">
                            <div class="card-header">
                                <h5 class="mb-0">Update Your Profile</h5>
                            </div>
                            <div class="card-body">
                                <?php if ($message): ?>
                                    <div class="alert alert-success" role="alert">
                                        <?php echo htmlspecialchars($message); ?>
                                    </div>
                                <?php endif; ?>
                                
                                <form method="post">
                                    <div class="mb-3">
                                        <label for="name" class="form-label">Name:</label>
                                        <input type="text" class="form-control" id="name" name="name" required>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label for="bio" class="form-label">Bio:</label>
                                        <textarea class="form-control" id="bio" name="bio" rows="3" required></textarea>
                                    </div>
                                    
                                    <button type="submit" class="btn btn-primary">Update Profile</button>
                                </form>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">Recent Profiles</h5>
                            </div>
                            <div class="card-body">
                                <?php if (empty($profiles)): ?>
                                    <p class="text-muted">No profiles yet. Create the first one!</p>
                                <?php else: ?>
                                    <?php foreach ($profiles as $profile): ?>
                                        <div class="border rounded p-3 mb-3">
                                            <h6>Name: <?php echo $profile['name']; ?></h6>
                                            <p>Bio: <?php echo $profile['bio']; ?></p>
                                        </div>
                                    <?php endforeach; ?>
                                <?php endif; ?>
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
                                    <li>✅ Execute stored XSS</li>
                                    <li>✅ Understand persistence</li>
                                    <li>✅ Analyze impact</li>
                                </ul>
                            </div>
                        </div>
                        
                        <div class="card mt-3">
                            <div class="card-header">
                                <h5 class="mb-0">🛠️ XSS Payloads</h5>
                            </div>
                            <div class="card-body">
                                <div class="accordion" id="payloadsAccordion">
                                    <div class="accordion-item">
                                        <h2 class="accordion-header">
                                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#basic">
                                                Basic Alert
                                            </button>
                                        </h2>
                                        <div id="basic" class="accordion-collapse collapse" data-bs-parent="#payloadsAccordion">
                                            <div class="accordion-body">
                                                <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="accordion-item">
                                        <h2 class="accordion-header">
                                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#cookie">
                                                Cookie Theft
                                            </button>
                                        </h2>
                                        <div id="cookie" class="accordion-collapse collapse" data-bs-parent="#payloadsAccordion">
                                            <div class="accordion-body">
                                                <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>
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