<?php
session_start(); 

$user_role = $_SESSION['user_role'];

if(!isset($_SESSION['user_role'])) {
    header('location: /laundry_system/homepage/homepage.php');
    exit();
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile</title>
    <link rel="stylesheet" href="profile.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"
        integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
    <link href="https://cdn.lineicons.com/4.0/lineicons.css" rel="stylesheet" />
    <link href='https://unpkg.com/boxicons@2.1.4/css/boxicons.min.css' rel='stylesheet'>
</head>

<body>
    <div class="progress"></div>
    <div class="wrapper">
        <aside id="sidebar">
            <div class="d-flex">
                <button id="toggle-btn" type="button">
                    <i class="bx bx-menu-alt-left"></i>
                </button>

                <div class="sidebar-logo">
                    <a href="#">Azia Skye</a>
                </div>
            </div>

            <ul class="sidebar-nav">
                <li class="sidebar-item">
                    <a href="/laundry_system/dashboard/dashboard.php" class="sidebar-link">
                        <i class="lni lni-grid-alt"></i>
                        <span>Dashboard</span>
                    </a>
              </li>

            <li class="sidebar-item">
                <a href="/laundry_system/profile/profile.php" class="sidebar-link">
                    <i class="lni lni-user"></i>
                    <span>Profile</span>
                </a>
            </li>

                <?php if ($user_role === 'admin') : ?>
                    <li class="sidebar-item">
                        <a href="/laundry_system/users/users.php" class="sidebar-link">
                            <i class="lni lni-users"></i>
                            <span>Users</span>
                        </a>
                    </li>

                    <li class="sidebar-item">
                        <a href="/laundry_system/records/records.php" class="sidebar-link has-dropdown collapsed" data-bs-toggle="collapse"
                            data-bs-target="#records" aria-expanded="false" aria-controls="records">
                            <i class="lni lni-files"></i>
                            <span>Records</span>
                        </a>

                        <ul id="records" class="sidebar-dropdown list-unstyled collapse" data-bs-parent="#sidebar">
                            <li class="sidebar-item">
                                <a href="/laundry_system/records/customer.php" class="sidebar-link">Customer</a>
                            </li>

                            <li class="sidebar-item">
                                <a href="/laundry_system/records/service.php" class="sidebar-link">Service</a>
                            </li>

                            <li class="sidebar-item">
                                <a href="/laundry_system/records/category.php" class="sidebar-link">Category</a>
                            </li>
                        </ul>
                    </li>
                <?php endif; ?>

                <li class="sidebar-item">
                    <a href="/laundry_system/transaction/transaction.php" class="sidebar-link">
                        <i class="lni lni-coin"></i>
                        <span>Transaction</span>
                    </a>
                </li>

                <li class="sidebar-item">
                    <a href="/laundry_system/sales_report/report.php" class="sidebar-link">
                        <i class='bx bx-line-chart'></i>
                        <span>Sales Report</span>
                    </a>
                </li>

                <?php if ($user_role === 'admin') : ?>
                    <li class="sidebar-item">
                        <a href="/laundry_system/settings/setting.php" class="sidebar-link">
                            <i class="lni lni-cog"></i>
                            <span>Settings</span>
                        </a>
                    </li>

                    <hr style="border: 1px solid #b8c1ec; margin: 8px">

                    <li class="sidebar-item">
                        <a href="/laundry_system/archived/archive_users.php" class="sidebar-link">
                            <i class='bx bxs-archive-in'></i>
                            <span class="nav-item">Archived</span>
                        </a>
                    </li>
                <?php endif; ?>
            </ul>

            <div class="sidebar-footer">
                <a href="/laundry_system/homepage/logout.php" class="sidebar-link">
                    <i class="lni lni-exit"></i>
                    <span>Logout</span>
                </a>
            </div>
        </aside>

        <div class="main p-3">
            <div class="header_con">
                <h1>Profile</h1>
            </div>

            <div class="user_container" id="user_container">
                <form action="" method="post" class="user_form" id="user_form">
                  <!--  <div class="row">
                        <div class="col">
                            <img id="profile-picture-preview" src="/laundry-ms/main/images/default_profile.png"
                                alt="Profile Picture Preview" class="img-fluid">
                        </div>
                    </div> -->

                    <div class="row">
                        <h4 class="text-center">Personal Details</h4>
                        <div class="col">
                            <label for="form-label">First Name</label>
                            <input type="text" id="fname" name="fname" class="form-control" disabled>
                        </div>
                        <div class="col">
                            <label for="form-label">Last Name</label>
                            <input type="text" name="lname" id="lname" class="form-control" disabled>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col">
                            <label for="form-label">Username</label>
                            <input type="text" id="username" name="username" class="form-control" disabled>
                        </div>
                    </div>

                    <div class="row">
                        <h4 class="text-center">Password</h4>
                        <div class="col">
                            <label for="form-label">Password</label>
                            <input type="password" id="password" name="password" class="form-control" disabled>
                        </div>
                    </div>

                    <div class="text-center">
                        <button type="button" class="btn btn-success" id="btn_edit">
                            <i class='bx bxs-edit'></i>
                            Edit Profile
                        </button>
                    </div>
                </form>
            </div>

            <div class="edit_user" id="edit_user">
                <form action="" method="post" class="edit_user_form" id="edit_user_form">
                    <div class="row">
                        <h3>Edit Profile</h3>
                        <p>Update your personal information.</p>
                        <hr>
                        <div class="col">
                            <label for="profilePicture" class="form-label">Profile Picture</label>
                            <br>
                            <img id="preview_profile_pic" src="/laundry-ms/main/images/default_profile.png"
                                alt="Profile Picture Preview">
                            <input class="form-control" type="file" id="updateProfilePicture"
                                accept="image/jpeg, image/png, image/jpg">
                        </div>
                    </div>

                    <div class="row">
                        <h4 class="text-center">Personal Details</h4>
                        <div class="col">
                            <label for="first_name" class="form-label">First Name</label>
                            <input type="text" id="edit_fname" name="edit_fname" class="form-control">
                        </div>
                        <div class="col">
                            <label for="last_name" class="form-label">Last Name</label>
                            <input type="text" id="edit_lname" name="edit_fname" class="form-control">
                        </div>
                    </div>
                    <div class="row">
                        <div class="col">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" id="edit_username" name="edit_username" class="form-control">
                        </div>
                    </div>

                    <div class="row">
                        <h4 class="text-center">Password</h4>
                        <div class="col">
                            <label for="current_pass" class="form-label">Current Password</label>
                            <input type="password" id="current_pass" name="current_pass" class="form-control">
                        </div>
                    </div>

                    <div class="row">
                        <div class="col">
                            <label for="new_pass" class="form-label">New Password</label>
                            <input type="password" id="new_pass" name="new_pass" class="form-control" minlength="8">
                        </div>
                    </div>

                    <div class="row">
                        <div class="col">
                            <label for="confirm_pass" class="form-label">Confirm Password</label>
                            <input type="password" id="confirm_pass" name="confirm_pass" class="form-control"
                                minlength="8">
                        </div>
                    </div>

                    <div class="text-center">
                        <button type="button" class="btn btn-light" id="btnBack">Back</button>
                        <button type="button" class="btn btn-primary" id="btnSaveChanges">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </div> <!-- wrapper-->

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz"
        crossorigin="anonymous"></script>
    <script src="https://unpkg.com/boxicons@2.1.4/dist/boxicons.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script type="text/javascript" src="profile.js"></script>
</body>

</html>