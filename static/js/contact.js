(function() {
    var fname = document.getElementById('form_name');
    var lname = document.getElementById('form_lastname');
    var email = document.getElementById('form_email');
    var message = document.getElementById('form_message');
    var submitButton = document.getElementById('form_submit');
    if(fname == '' || lname == '' ){
        submitButton.disabled = true
    }
})();