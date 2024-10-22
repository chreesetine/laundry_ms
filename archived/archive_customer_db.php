<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);  // Decode JSON input

    if (isset($input['id'])) {  
        $customerId = $input['id'];

        $conn = new mysqli('localhost', 'root', '', 'laundry_db');
        if ($conn->connect_error) {
            error_log("Database connection failed: " . $conn->connect_error);
            echo json_encode(['success' => false, 'error' => 'Database connection failed']);
            exit();
        }

        // Query customer table
        $sql = "SELECT * FROM customer WHERE customer_id = ?";
        $stmt = $conn->prepare($sql);
        if (!$stmt) {
            error_log("Prepare failed: " . $conn->error);
            echo json_encode(['success' => false, 'error' => 'Failed to prepare SQL statement']);
            exit();
        }
        
        $stmt->bind_param("i", $customerId);
        $stmt->execute();
        $result = $stmt->get_result();
        $customer = $result->fetch_assoc();

        if ($customer) {
            // Insert into archived_customer table
            $archiveSql = "INSERT INTO archived_customers (customer_id, customer_name, contact_number, address, archived_at) VALUES (?, ?, ?, ?, NOW())";
            $archiveStmt = $conn->prepare($archiveSql);
            if (!$archiveStmt) {
                error_log("Prepare failed for archive: " . $conn->error);
                echo json_encode(['success' => false, 'error' => 'Failed to prepare archive SQL']);
                exit();
            }
            $archiveStmt->bind_param("isss", $customer['customer_id'], $customer['customer_name'], $customer['contact_number'], $customer['address']);
            $archiveStmt->execute();

            if ($archiveStmt->affected_rows > 0) {
                // Delete customer from the customer table
                $deleteSql = "DELETE FROM customer WHERE customer_id = ?";
                $deleteStmt = $conn->prepare($deleteSql);
                if (!$deleteStmt) {
                    error_log("Prepare failed for delete: " . $conn->error);
                    echo json_encode(['success' => false, 'error' => 'Failed to prepare delete SQL']);
                    exit();
                }
                $deleteStmt->bind_param("i", $customerId);
                $deleteStmt->execute();

                if ($deleteStmt->affected_rows > 0) {
                    echo json_encode(['success' => true]);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Failed to delete customer']);
                }
            } else {
                echo json_encode(['success' => false, 'error' => 'Failed to archive customer']);
            }
        } else {
            echo json_encode(['success' => false, 'error' => 'Customer not found']);
        }

        $stmt->close();
        $archiveStmt->close();
        $deleteStmt->close();
        $conn->close();
    } else {
        echo json_encode(['success' => false, 'error' => 'Customer ID missing']);
    }
} else {
    echo json_encode(['success' => false, 'error' => 'Invalid request method']);
}
?>