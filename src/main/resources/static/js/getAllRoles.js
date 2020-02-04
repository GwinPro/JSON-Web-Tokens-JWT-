$(document).ready(function () {
    getAllRolesForAddForm();
});

function getAllRolesForAddForm() {
    fetch("/rest/admin/roles").then(function (response) {
        response.json().then(function (data) {
            let selectBody = "";
            selectBody = $('#newUser-role');
            $(data).each(function (i, role) {
                selectBody.append(`<option value="${role.id}">${role.role}</option>`);
            })
        })
    });
}