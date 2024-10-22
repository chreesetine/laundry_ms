const hamburger = document.querySelector("#toggle-btn");

hamburger.addEventListener("click",function() {
    document.querySelector("#sidebar").classList.toggle("expand");
})

$(document).ready(function(){
    function showEditUserForm () {
        $('#user_container').hide();
        $('#edit_user').show();
    }

    function showUserContainer () {
        $('#edit_user').hide(); 
        $('#user_container').show();
    }

    $('#btn_edit').click(function(){
        showEditUserForm();
    });

    $('#btnBack').click(function(){
        showUserContainer();
    });

    // Fetch user data when the page loads
    $.ajax({
      type: 'GET',
      url: '/laundry-ms/main/my_profile/configs_profile/get_user_data.php',
      dataType: 'json',
      success: function(data) {
          // Display user data
          $('#fname').val(data.first_name);
          $('#lname').val(data.last_name);
          $('#username').val(data.username);
          $('#password').val(data.password);
          $('#profile-picture-preview').attr('src', data.profile_picture);
      }
  });

});

let preview_profile_pic = document.getElementById("preview_profile_pic");
let updateProfilePicture = document.getElementById("updateProfilePicture");

updateProfilePicture.onchange = function(){
    preview_profile_pic.src =   URL.createObjectURL(updateProfilePicture.files[0]);
}