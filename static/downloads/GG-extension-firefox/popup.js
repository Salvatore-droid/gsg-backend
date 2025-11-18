// Popup script
document.addEventListener('DOMContentLoaded', () => {
    const statusDiv = document.getElementById('status');
    const startBtn = document.getElementById('startBtn');
    const stopBtn = document.getElementById('stopBtn');
    const sessionInfo = document.getElementById('sessionInfo');
    const sessionIdSpan = document.getElementById('sessionId');
    
    // Check current status when popup opens
    checkStatus();
    
    startBtn.addEventListener('click', () => {
      const sessionId = prompt('Enter session ID (or leave empty for auto-generated):');
      if (sessionId !== null) {
        startRecording(sessionId || generateSessionId());
      }
    });
    
    stopBtn.addEventListener('click', () => {
      stopRecording();
    });
    
    function checkStatus() {
      chrome.runtime.sendMessage({ action: 'GET_STATUS' }, (response) => {
        if (chrome.runtime.lastError) {
          updateUI({ connected: false, isRecording: false });
          return;
        }
        updateUI(response);
      });
    }
    
    function startRecording(sessionId) {
      chrome.runtime.sendMessage({ 
        action: 'START_RECORDING', 
        sessionId: sessionId 
      }, (response) => {
        if (chrome.runtime.lastError) {
          alert('Error starting recording: ' + chrome.runtime.lastError.message);
          return;
        }
        
        if (response && response.status === 'recording_started') {
          updateUI({ isRecording: true, connected: true, sessionId: sessionId });
          // Notify the main page that recording started
          notifyMainPage('recording_started', { sessionId: sessionId });
        } else {
          alert('Failed to start recording');
        }
      });
    }
    
    function stopRecording() {
      chrome.runtime.sendMessage({ action: 'STOP_RECORDING' }, (response) => {
        if (chrome.runtime.lastError) {
          alert('Error stopping recording: ' + chrome.runtime.lastError.message);
          return;
        }
        
        if (response && response.status === 'recording_stopped') {
          updateUI({ isRecording: false, connected: true });
          // Notify the main page that recording stopped
          notifyMainPage('recording_stopped');
        } else {
          alert('Failed to stop recording');
        }
      });
    }
    
    function generateSessionId() {
      return 'session-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
    }
    
    function updateUI(status) {
      if (!status) {
        statusDiv.textContent = '❌ Not Connected';
        statusDiv.className = 'status disconnected';
        startBtn.disabled = true;
        stopBtn.disabled = true;
        sessionInfo.style.display = 'none';
        return;
      }
      
      if (status.connected) {
        if (status.isRecording) {
          statusDiv.textContent = '🔴 Recording Active';
          statusDiv.className = 'status recording';
          startBtn.disabled = true;
          stopBtn.disabled = false;
          sessionInfo.style.display = 'block';
          sessionIdSpan.textContent = status.sessionId || 'Unknown';
        } else {
          statusDiv.textContent = '✅ Connected - Ready';
          statusDiv.className = 'status connected';
          startBtn.disabled = false;
          stopBtn.disabled = true;
          sessionInfo.style.display = 'none';
        }
      } else {
        statusDiv.textContent = '❌ Not Connected';
        statusDiv.className = 'status disconnected';
        startBtn.disabled = true;
        stopBtn.disabled = true;
        sessionInfo.style.display = 'none';
      }
    }
    
    function notifyMainPage(action, data = {}) {
      // Try to notify the main GeniusGuard page
      chrome.tabs.query({ url: 'http://localhost:8000/*' }, (tabs) => {
        tabs.forEach(tab => {
          chrome.tabs.sendMessage(tab.id, {
            action: 'EXTENSION_' + action.toUpperCase(),
            ...data
          }).catch(err => {
            console.log('Could not notify main page:', err);
          });
        });
      });
    }
  });