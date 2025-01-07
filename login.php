<?php
session_start();
include('db.php');
include('security.php');

if($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $otp = $_POST['otp'];

    //fetching user from database
    $sql = "SELECT * FROM users WHERE username = ?";
    $stmt = $conn->prepare($sql);
    $stmt ->bind_param("s", $username );
    $stmt ->execute();
    $result = $stmt->get_result();

    if($result->num_rows > 0) {
        $user = $result->fetch_assoc();

        if(password_verify($password, $user['password'])) {

            //verifyingn OTP if 2FA is enabled
            if(!empty($user['otpSecret'])) {
                if (!verifyOtp($user['otpSecret'], $otp)) {
                    echo "Invalid OTP!" ;
                    exit();
                }
            }

            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            echo "Login successful!";

        } else {
            echo "Invalid credentials!";
        }
    }  else {
        echo "User not found!";
    }
}
?>
    