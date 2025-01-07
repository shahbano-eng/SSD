<?php
session_start(); // Start session for OTP handling
include('session.php');
include('register2.php');
// Database connection details
$servername = "localhost"; // Replace with your server name
$db_username = "user1";    // Replace with your database username
$db_password = "user1";    // Replace with your database password
$dbname = "gift_shop";     // Your database name

// Create connection
$conn = new mysqli($servername, $db_username, $db_password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Handle Registration
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email']) && isset($_POST['username']) && isset($_POST['pass']) && isset($_POST['date_of_birth'])) {
    $username = $_POST['username'];
    $email = $_POST['email'];
    $password = $_POST['pass'];
    $dob = $_POST['date_of_birth'];
    $phone = $_POST['phone-number'];
    $created_at = date('Y-m-d H:i:s');

    // Secure the inputs
    $username = $conn->real_escape_string($username);
    $email = $conn->real_escape_string($email);
    $dob = $conn->real_escape_string($dob);
    $phone = $conn->real_escape_string($phone);
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Check if username or email already exists
    $sql_check = "SELECT * FROM users WHERE username = ? OR email = ?";
    $stmt_check = $conn->prepare($sql_check);
    $stmt_check->bind_param("ss", $username, $email);
    $stmt_check->execute();
    $result_check = $stmt_check->get_result();

    if ($result_check->num_rows > 0) {
        echo "Username or email already exists.";
    } else {
        // Insert the new user into the database
        $sql_insert = "INSERT INTO users (username, password, email, phone_number, date_of_birth, created_at) VALUES (?, ?, ?, ?, ?, ?)";
        $stmt_insert = $conn->prepare($sql_insert);
        $stmt_insert->bind_param("ssssss", $username, $hashed_password, $email, $phone, $dob, $created_at);

        if ($stmt_insert->execute()) {
            // Generate OTP
            $otp = rand(100000, 999999); // 6-digit OTP
            $_SESSION['otp'] = $otp; // Store OTP in session
            $_SESSION['username'] = $username; // Temporarily store username

            // Display OTP to the user (for testing, usually sent via email/SMS)
            echo "Registration successful! Your OTP is: <strong>$otp</strong><br>";
            echo "<a href='verify_otp.php'>Click here to verify your OTP</a>";
        } else {
            echo "Error during registration: " . $stmt_insert->error;
        }
    }

    $stmt_check->close();
    $stmt_insert->close();
}

// Handle Login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username']) && isset($_POST['pass']) && !isset($_POST['email'])) {
    $username = $_POST['username'];
    $password = $_POST['pass'];

    $username = $conn->real_escape_string($username);

    

    $sql_login = "SELECT * FROM users WHERE username = ?";
    $stmt_login = $conn->prepare($sql_login);
    $stmt_login->bind_param("s", $username);
    $stmt_login->execute();
    $result_login = $stmt_login->get_result();

    if ($result_login->num_rows === 1) {
        $user = $result_login->fetch_assoc();
        if (password_verify($password, $user['password'])) {
            echo "Login successful. Welcome, " . $user['username'] . "!";
            header("Location: OrderHtml.html");
        } else {
            echo "Invalid username or password.";
        }
    } else {
        echo "Invalid username or password.";
    }
    
    $stmt_login->close();
}

$conn->close();
?>
