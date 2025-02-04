document.addEventListener('DOMContentLoaded', () => {
    const hamburger = document.querySelector("#toggle-btn");

    hamburger.addEventListener("click",function() {
        document.querySelector("#sidebar").classList.toggle("expand");
    });

    // add service 
    const addModal = document.getElementById('addModal');
    const addServiceButton = document.getElementById('addServiceButton');
    const closeAddServiceButton = document.querySelector('.close');
    const clearButton = document.querySelector('.btn-info');

    addServiceButton.addEventListener('click', () => {
        console.log("Add Service Button Clicked");
        addModal.style.display = 'block';
    });

    closeAddServiceButton.addEventListener('click', () => {
        addModal.style.display = 'none';
    });

    clearButton.addEventListener('click', () => {
        document.getElementById('form').reset();
    });

    window.addEventListener('click', (event) => {
        if (event.target === addModal) {
            addModal.style.display = 'none';
        }
    });

    const form = document.getElementById('form');

    form.addEventListener('submit', function (event) {
        event.preventDefault();

        const formData = new FormData(form);

        fetch('add_service.php', {
            method: 'POST',
            body: formData
        })

        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('New laundry service option saved successfully!');
                form.reset();
                $('#addModal').modal('hide');
            } else {
                alert('Error: ' + data.message);
            }
        })

        .catch(error => {
            console.error('Error:', error);
            alert('There was an error submiting the form. Please try again.');
        });
    });

    // archive function 
    const archiveModal = document.getElementById('archiveModal');
    const confirmArchiveButton = document.getElementById('confirmArchiveButton');
    const cancelArchiveButton = document.getElementById('cancelArchiveButton');
    const closeArchiveModal = document.getElementById('closeArchiveModal');

    // success
    const successModal = document.getElementById('successModal');
    const closeSuccessModal = document.getElementById('closeSuccessModal');
    const closeSuccessButton = document.getElementById('closeSuccessButton');

    let serviceIdToArchive = null;

    document.querySelectorAll('.archive-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            serviceIdToArchive = btn.dataset.id;
            archiveModal.style.display = 'block';
        });
    });    

    closeArchiveModal.addEventListener('click', () => {
        archiveModal.style.display = 'none';
    });

    cancelArchiveButton.addEventListener('click', () => {
        archiveModal.style.display = 'none';
    });

    confirmArchiveButton.addEventListener('click', () => {
        fetch('/laundry_system/archived/archive_service_db.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }, 
            body: JSON.stringify({ id: serviceIdToArchive })
        })

        .then(response => response.text())
        .then(data => {
            console.log('Raw response:', data);

            if (data.trim().startsWith('<')) {
                console.log('Received HTML instead of JSON:', data);
                return;
            }

            try {
                const jsonData = JSON.parse(data);

                if (jsonData.success) {
                        archiveModal.style.display = 'none';
                        successModal.style.display = 'block';
                } else {
                        alert('Error archiving service option" ' + jsonData.error);
                } 
            } catch(error) {
                console.error('Error parsing JSON:', error, data);
            }
        })

        .catch(error => {
            console.error('Fetch error:', error);
        });
    });

    closeSuccessButton.addEventListener('click', () => {
        successModal.style.display = 'none';
        location.reload();
    });

    /* search */
    $("#filter_service").on("keyup", function() {
        var value = $(this).val().toLowerCase();
        $("#service_table tr").filter(function() {
          $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
    });
});