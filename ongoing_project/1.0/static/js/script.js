// JavaScript to toggle the upload form and investigation option
        const bddsToggle = document.getElementById("bddsToggle");
        const uploadContainer = document.getElementById("uploadContainer");
        const investigationContainer = document.getElementById("investigationContainer");
        const uploadStatus = document.getElementById("upload-status");

        bddsToggle.addEventListener("click", function (event) {
            event.preventDefault();
            uploadContainer.classList.toggle("hidden");
            investigationContainer.classList.add("hidden");
            uploadStatus.classList.add("hidden");
        });

        // Function to show the upload status message
        function showUploadStatusMessage(message) {
            uploadStatus.textContent = message;
            uploadStatus.classList.remove("hidden");
            setTimeout(function () {
                uploadStatus.classList.add("hidden");
            }, 3000); // Hide the message after 3 seconds
        }

        // Function to handle the file upload using AJAX
        function uploadFile() {
            const fileInput = document.getElementById("file");
            const uploadMessage = document.getElementById("upload-message");

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                uploadMessage.value = data.message;
                showUploadStatusMessage(data.message);
                fileInput.value = ''; // Clear the file input
                if (data.message === "File successfully uploaded") {
                    investigationContainer.classList.remove("hidden");
                }
            })
            .catch(error => {
                uploadMessage.value = "File upload failed";
                showUploadStatusMessage("File upload failed");
            });
        }

// Add an event listener to the "Start Investigation" button
document.getElementById("startInvestigation").addEventListener("click", function () {
    const spinner = document.getElementById("spinner");
    const downloadLink = document.getElementById("downloadLink");
    const spinnerText = document.querySelector(".spinner-text");

    spinnerText.textContent = "Starting Investigation...";

    spinner.classList.remove("hidden"); // Show the spinner

    fetch('/start-investigation', {
        method: 'POST',
    })
    .then(response => response.json())
    .then(data => {
        if (data.fileUrl) {
            spinnerText.textContent = "Investigation completed. Preparing for download.";
            downloadLink.href = `/download?filename=${data.fileUrl}`;
            downloadLink.style.display = "block";
        } else {
            alert(data.message);
            spinnerText.textContent = "Investigation failed.";
        }
    })
    .catch(error => {
        // Handle errors
        spinnerText.textContent = "Investigation failed.";
        alert("Investigation request failed");
    })
    .finally(() => {
        // Hide the spinner after the investigation is completed or failed

    });
});


// Function to extract filename from a URL
function getFileNameFromUrl(url) {
    const urlParts = url.split('/');
    return urlParts[urlParts.length - 1];
    }

