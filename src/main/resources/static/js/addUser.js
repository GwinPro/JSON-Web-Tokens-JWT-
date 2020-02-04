$(document).ready(function () {
    $('#addUserButton').click(function () {
        fetchPostAddUser();
    });

    function fetchPostAddUser() {
        let roleValue = "";
        let role = document.getElementById("newUser-role");
        if (role[role.selectedIndex].value === 2) {
            roleValue = "ROLE_ADMIN";
        } else {
            roleValue = "ROLE_USER";
        }

        // Create JSON object
        let addData = {
            email: $('#inputEmail').val(),
            login: $('#inputLogin').val(),
            password: $('#inputPassword').val(),
            roles: [{
                id: role[role.selectedIndex].value,
                role: roleValue,
                authority: roleValue
            }]
        };

        // DO POST
        fetch("/rest/admin/addUser", {
            method: 'post',
            body: JSON.stringify(addData),
            headers: {
                'content-type': 'application/json'
            }
        }).then(function () {
            document.location.reload();
        })
    }
});