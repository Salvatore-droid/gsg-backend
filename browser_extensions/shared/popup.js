// Popup script - handles UI interactions
class GeniusGuardPopup {
    constructor() {
      this.recording = false;
      this.sessionId = null;
      this.init();
    }
  
    async init() {
      await this.checkStatus();
      this.setupEventListeners();
    }
  
    async checkStatus() {
      try {
        const response = await this.sendMessage({ action: 'GET_STATUS' });
        this.updateUI(response);
      } catch (error) {
        console.error('Status check failed:', error);
        this.updateUI({ recording: false, sessionId: null, actionsCount: 0 });
      }
    }
  
    sendMessage(message) {
      return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(message, (response) => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve(response);
          }
        });
      });
    }
  
    setupEventListeners() {
      document.getElementById('connectBtn').addEventListener('click', () => {
        this.connectToDashboard();
      });
  
      document.getElementById('recordBtn').addEventListener('click', () => {
        this.startRecording();
      });
  
      document.getElementById('stopBtn').addEventListener('click', () => {
        this.stopRecording();
      });
    }
  
    async connectToDashboard() {
      try {
        // Try to communicate with the dashboard page
        const tabs = await new Promise(resolve => {
          chrome.tabs.query({ url: 'http://localhost:5173/*' }, resolve);
        });
  
        if (tabs.length > 0) {
          // Send connection message to dashboard
          chrome.tabs.sendMessage(tabs[0].id, { 
            action: 'EXTENSION_CONNECTED',
            version: '1.0.0'
          });
  
          this.updateStatus('Connected to Dashboard', 'idle');
          document.getElementById('recordBtn').disabled = false;
        } else {
          this.updateStatus('Dashboard not found', 'idle');
        }
      } catch (error) {
        console.error('Connection failed:', error);
        this.updateStatus('Connection failed', 'idle');
      }
    }
  
    async startRecording() {
      try {
        // Generate a session ID
        this.sessionId = 'session-' + Date.now();
        
        const response = await this.sendMessage({
          action: 'START_RECORDING',
          sessionId: this.sessionId
        });
  
        if (response.status === 'recording_started') {
          this.recording = true;
          this.updateUI({ recording: true, sessionId: this.sessionId });
          this.updateStatus('Recording Started', 'recording');
        }
      } catch (error) {
        console.error('Start recording failed:', error);
        this.updateStatus('Start failed', 'idle');
      }
    }
  
    async stopRecording() {
      try {
        const response = await this.sendMessage({ action: 'STOP_RECORDING' });
  
        if (response.status === 'recording_stopped') {
          this.recording = false;
          this.updateUI({ recording: false, sessionId: null });
          this.updateStatus('Recording Stopped', 'idle');
        }
      } catch (error) {
        console.error('Stop recording failed:', error);
        this.updateStatus('Stop failed', 'idle');
      }
    }
  
    updateUI(status) {
      const statusEl = document.getElementById('status');
      const statusText = document.getElementById('statusText');
      const sessionInfo = document.getElementById('sessionInfo');
      const sessionIdEl = document.getElementById('sessionId');
      const actionsCountEl = document.getElementById('actionsCount');
      const recordBtn = document.getElementById('recordBtn');
      const stopBtn = document.getElementById('stopBtn');
  
      if (status.recording) {
        statusText.textContent = 'Recording Session';
        statusEl.className = 'status recording';
        sessionInfo.style.display = 'block';
        sessionIdEl.textContent = status.sessionId?.substring(0, 8) + '...';
        actionsCountEl.textContent = status.actionsCount || 0;
        recordBtn.disabled = true;
        stopBtn.disabled = false;
      } else {
        statusText.textContent = 'Ready';
        statusEl.className = 'status idle';
        sessionInfo.style.display = 'none';
        recordBtn.disabled = false;
        stopBtn.disabled = true;
      }
    }
  
    updateStatus(message, type) {
      const statusText = document.getElementById('statusText');
      const statusEl = document.getElementById('status');
      
      statusText.textContent = message;
      statusEl.className = `status ${type}`;
    }
  }
  
  // Initialize the popup
  document.addEventListener('DOMContentLoaded', () => {
    new GeniusGuardPopup();
  });