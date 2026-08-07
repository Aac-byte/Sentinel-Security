const fileInput = document.getElementById("fileElem");
const fileName = document.getElementById("file-name");
const dropArea = document.getElementById("drop-area");

if (fileInput && fileName && dropArea) {

    fileInput.addEventListener("change", function () {

        if (fileInput.files.length > 0) {

            fileName.innerHTML =
                "Selected File : " + fileInput.files[0].name;

        }

    });

    ["dragenter", "dragover"].forEach(function(eventName){

        dropArea.addEventListener(eventName, function(e){

            e.preventDefault();

            dropArea.classList.add("highlight");

        });

    });

    ["dragleave", "drop"].forEach(function(eventName){

        dropArea.addEventListener(eventName, function(e){

            e.preventDefault();

            dropArea.classList.remove("highlight");

        });

    });

    dropArea.addEventListener("drop", function(e){

        fileInput.files = e.dataTransfer.files;

        if(fileInput.files.length > 0){

            fileName.innerHTML =
                "Selected File : " + fileInput.files[0].name;

        }

    });

}