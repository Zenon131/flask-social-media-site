// ajax-handlers.js

// Function to update the user's status using AJAX
function updateStatus() {
    var statusText = document.getElementById('status').value;

    // Create a new XMLHttpRequest object
    var xhr = new XMLHttpRequest();

    // Configure it: POST-request for the /update_status endpoint
    xhr.open('POST', '/community-feed', true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    // Setup a callback function to handle the response
    xhr.onload = function () {
        if (xhr.status === 200) {
            // Parse the JSON response
            var data = JSON.parse(xhr.responseText);
            // Handle the success response (if needed)
            console.log(data);
            // You can update the DOM here if necessary
        } else {
            // Handle the error response (if needed)
            console.error(xhr.statusText);
        }
    };

    // Convert the data to JSON and send the request
    xhr.send(JSON.stringify({ status_text: statusText }));
}

// Function to add a comment using AJAX
function addComment(entryId) {
    var commentText = document.getElementById('comment').value;

    // Create a new XMLHttpRequest object
    var xhr = new XMLHttpRequest();

    // Configure it: POST-request for the /add_comment endpoint
    xhr.open('POST', '/community-feed', true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    // Setup a callback function to handle the response
    xhr.onload = function () {
        if (xhr.status === 200) {
            // Parse the JSON response
            var data = JSON.parse(xhr.responseText);
            // Handle the success response (if needed)
            console.log(data);
            // You can update the DOM here if necessary
        } else {
            // Handle the error response (if needed)
            console.error(xhr.statusText);
        }
    };

    // Convert the data to JSON and send the request
    xhr.send(JSON.stringify({ entry_id: entryId, comment_text: commentText }));
}
