document.addEventListener('DOMContentLoaded', () => {
    const statusDiv = document.getElementById('status');
    const startBtn = document.getElementById('start-recording');
    const stopBtn = document.getElementById('stop-recording');
    const backendUrlInput = document.getElementById('backend-url');
    const authTokenInput = document.getElementById('auth-token');
    const saveSettingsBtn = document.getElementById('save-settings');

    // Load saved settings
    chrome.storage.local.get(['backendUrl', 'authToken'], (result) => {
        if (result.backendUrl) backendUrlInput.value = result.backendUrl;
        if (result.authToken) authTokenInput.value = result.authToken;
        checkConnection();
    });

    updateRecordingStatus();

    startBtn.addEventListener('click', () => {
        const sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        chrome.runtime.sendMessage({ 
            action: 'startRecording',
            sessionId: sessionId
        }, (response) => {
            if (response && response.status === 'recording_started') {
                updateRecordingStatus();
            }
        });
    });

    stopBtn.addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: 'stopRecording' }, (response) => {
            if (response && response.status === 'recording_stopped') {
                updateRecordingStatus();
            }
        });
    });

    saveSettingsBtn.addEventListener('click', () => {
        const backendUrl = backendUrlInput.value.trim();
        const authToken = authTokenInput.value.trim();
        
        if (backendUrl && authToken) {
            chrome.storage.local.set({ 
                backendUrl: backendUrl,
                authToken: authToken 
            }, () => {
                showStatus('Settings Saved', 'connected');
                checkConnection();
            });
        }
    });

    function updateRecordingStatus() {
        chrome.runtime.sendMessage({ action: 'getRecordingStatus' }, (response) => {
            if (response) {
                if (response.isRecording) {
                    showStatus('Recording Active', 'recording');
                    startBtn.disabled = true;
                    stopBtn.disabled = false;
                } else {
                    showStatus('Ready to Record', 'stopped');
                    startBtn.disabled = false;
                    stopBtn.disabled = true;
                }
            }
        });
    }

    function checkConnection() {
        chrome.runtime.sendMessage({ action: 'checkConnection' }, (response) => {
            if (response && response.status === 'connected') {
                showStatus('Connected to Backend', 'connected');
            }
        });
    }

    function showStatus(message, type) {
        statusDiv.textContent = message;
        statusDiv.className = 'status ' + type;
    }
});