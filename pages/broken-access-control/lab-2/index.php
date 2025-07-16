<?php
$page_title = "Broken Access Control Lab 2 - Horizontal Privilege Escalation";
require_once '../../../config/env.php';
require_once '../../../template/header.php';

define("ENCRYPT_METHOD", "AES-256-CBC");
define("SECRET_KEY","thisismysecretkey");
define("SECRET_IV", "secretiv");
function encriptar($action, $string)
{
  $output = false;
  $key    = hash("sha256", SECRET_KEY);
  $iv     = substr(hash("sha256", SECRET_IV), 0, 16);

  if ($action == "encrypt")
  {
    $output = openssl_encrypt($string, ENCRYPT_METHOD, $key, 0, $iv);
    $output = base64_encode($output);
  }
  else if($action == "decrypt")
    {
        $output = base64_decode($string);
        $output = openssl_decrypt($output, ENCRYPT_METHOD, $key, 0, $iv);
    }
  return $output;
}

$user_id = null;
if (isset($_GET['user_id'])) {
    $user_id = encriptar('decrypt', $_GET['user_id']);
}

$current_user = $user_id ?? null;
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
                                <li class="breadcrumb-item"><a href="../">Broken Access Control</a></li>
                                <li class="breadcrumb-item active">Lab 2</li>
                            </ol>
                        </nav>
                        
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h1 class="h2">Lab 2: Horizontal Privilege Escalation</h1>
                            <span class="lab-difficulty difficulty-easy">Easy</span>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-8">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">User Profile Viewer</h5>
                            </div>
                            <div class="card-body">
                                <p>You are currently viewing identity for User ID: <?php echo htmlspecialchars($user_id??0); ?></p>
                                <!-- eTZpZ1BrWkNGQlVOdzY4WG4rQm4yUT09 id 1 -->
                                <!-- OEo2OExMQ3dmUHdHOS9CTGNINHNPQT09 id 3 -->
                                <!-- R0djSXpPYXA4cmw3QlJHOFhVMStrUT09 id 5 -->
                                <?php if ($current_user): ?>
                                    <div class="alert alert-info" role="alert">
                                        <h5>KTP:</h5>
                                        <p><img src="../../../uploads/identity/ktp_user_<?php echo htmlspecialchars($current_user); ?>.jpg" alt=""></p>
                                    </div>
                                <?php else: ?>
                                    <div class="alert alert-danger" role="alert">
                                        KTP not found.
                                    </div>
                                <?php endif; ?>
                                
                                <div class="mt-4">
                                    <h6>Quick Navigation:</h6>
                                    <a href="?user_id=1" class="btn btn-outline-primary me-2">KTP User 1</a>
                                    <a href="?user_id=3" class="btn btn-outline-primary me-2">KTP User 2</a>
                                    <a href="?user_id=5" class="btn btn-outline-primary">KTP User 3</a>
                                    <a href="?user_id=eTZpZ1BrWkNGQlVOdzY4WG4rQm4yUT09" class="btn btn-outline-primary me-2">KTP User 1 Encrypt</a>
                                    <a href="?user_id=OEo2OExMQ3dmUHdHOS9CTGNINHNPQT09" class="btn btn-outline-primary me-2">KTP User 2 Encrypt</a>
                                    <a href="?user_id=R0djSXpPYXA4cmw3QlJHOFhVMStrUT09" class="btn btn-outline-primary">KTP User 3 Encrypt</a>
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
                                    <li>✅ Access other users' profiles</li>
                                    <li>✅ Enumerate user data</li>
                                    <li>✅ Understand IDOR vulnerability</li>
                                </ul>
                            </div>
                        </div>
                        
                        <div class="card mt-3">
                            <div class="card-header">
                                <h5 class="mb-0">🛠️ IDOR Techniques</h5>
                            </div>
                            <div class="card-body">
                                <div class="accordion" id="techniquesAccordion">
                                    <div class="accordion-item">
                                        <h2 class="accordion-header">
                                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#enumeration">
                                                User ID Enumeration
                                            </button>
                                        </h2>
                                        <div id="enumeration" class="accordion-collapse collapse" data-bs-parent="#techniquesAccordion">
                                            <div class="accordion-body">
                                                Try different user_id values in the URL: ?user_id=1, ?user_id=2, ?user_id=3
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