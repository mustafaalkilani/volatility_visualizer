const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const fileInfo = document.getElementById('fileInfo');
const fileName = document.getElementById('fileName');
const fileSize = document.getElementById('fileSize');
const uploadBtn = document.getElementById('uploadBtn');
const visualizeBtn = document.getElementById('visualizeBtn');
const message = document.getElementById('message');
const progressContainer = document.getElementById('progressContainer');
const progressBar = document.getElementById('progressBar');
let selectedFile = null;
let processedFileName = null;
uploadArea.addEventListener('click', () => {
    fileInput.click();
});
uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.classList.add('dragover');
});
uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('dragover');
});
uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.classList.remove('dragover');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFileSelect(files[0]);
    }
});
fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
    }
});
function handleFileSelect(file) {
    if (!file.name.toLowerCase().endsWith('.txt')) {
        showMessage('Please select a .txt file containing Volatility process scan output.', 'error');
        return;
    }
    selectedFile = file;
    
    fileName.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
    fileInfo.style.display = 'flex';
    
    uploadBtn.disabled = false;
    
    hideMessage();
}
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
uploadBtn.addEventListener('click', async () => {
    if (!selectedFile) return;
    const formData = new FormData();
    formData.append('file', selectedFile);
    progressContainer.style.display = 'block';
    uploadBtn.disabled = true;
    uploadBtn.textContent = 'Processing...';
    try {
        let progress = 0;
        const progressInterval = setInterval(() => {
            progress += Math.random() * 30;
            if (progress > 90) progress = 90;
            progressBar.style.width = progress + '%';
        }, 200);
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();
        
        clearInterval(progressInterval);
        progressBar.style.width = '100%';
        if (result.success) {
            processedFileName = result.json_file;
            showMessage(result.message, 'success');
            visualizeBtn.style.display = 'inline-block';
            uploadBtn.textContent = 'Upload Complete ✓';
        } else {
            showMessage(result.error, 'error');
            uploadBtn.disabled = false;
            uploadBtn.textContent = 'Upload & Analyze';
        }
    } catch (error) {
        showMessage('Upload failed: ' + error.message, 'error');
        uploadBtn.disabled = false;
        uploadBtn.textContent = 'Upload & Analyze';
    }
    setTimeout(() => {
        progressContainer.style.display = 'none';
        progressBar.style.width = '0%';
    }, 1000);
});
visualizeBtn.addEventListener('click', () => {
    if (processedFileName) {
        window.location.href = `/visualizer?data=${encodeURIComponent(processedFileName)}`;
    }
});
function showMessage(text, type) {
    message.textContent = text;
    message.className = `message ${type}`;
    message.style.display = 'block';
}
function hideMessage() {
    message.style.display = 'none';
}