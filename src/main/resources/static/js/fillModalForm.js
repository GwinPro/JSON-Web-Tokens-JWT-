/*function fillUpdateModalForm(id) {
    $.ajax({
        url: '/api/users/' + id,
        method: "GET",
        dataType: "json",
        success: function (data) {
            $('#modalId').val(data.id);
            $('#modalName').val(data.name);
            $('#modalLogin').val(data.login);
            $('#modalPassword').val(data.password);
        },
        error: function (error) {
            alert(error);
        }
    })
}*/

function fillModalForm(id){
    let url = "/rest/admin/updateUser/"+id;
    fetch(url).then(function(response) {
        response.json().then(function(data) {
            $('#inputModalId').val(data.id);
            $('#inputModalEmail').val(data.email);
            $('#inputModalLogin').val(data.login);
            $('#inputModalPassword').val(data.password);
        });
    });
}
