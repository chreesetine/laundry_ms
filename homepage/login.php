<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['username']) && isset($_POST['password'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];

        $conn = new mysqli('localhost', 'root', '', 'laundry_db');

        if ($conn->connect_error) {
            die('Failed to connect: ' . $conn->connect_error);
        } else {
            // Prepare the SQL statement to prevent SQL injection
            $stmt = $conn->prepare("SELECT * FROM user WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $stmt_result = $stmt->get_result();

            // Check if any user found
            if ($stmt_result->num_rows > 0) {
                $data = $stmt_result->fetch_assoc();

                // Validate password using password_verify
                if (password_verify($password, $data['password'])) {
                    $_SESSION['user_role'] = $data['user_role'];
                    $_SESSION['username'] = $username;

                    header('Location: /laundry_system/dashboard/dashboard.php');
                    exit();
                } else {
                    echo "<script>alert('Mismatch password')</script>";
                }
            } else {
                echo "<script>alert('Invalid username or password')</script>";
            }
        }
        // Close the statement
        $stmt->close();
        // Close the connection
        $conn->close();
    } else {
        echo "<script>alert('Please enter both username and password.')</script>";
    }
} else {
    echo "<script>alert('Invalid access. Please use the login form.');</script>";
}
?>
