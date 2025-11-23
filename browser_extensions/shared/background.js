// Background script - manages extension state
class GeniusGuardBackground {
    constructor() {
      this.recording = false;
      this.sessionId = null;
      this.actions = [];
      this.init();
    }
  
    init() {
      // Handle messages from content scripts and popup
      chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        switch (request.action) {
          case 'START_RECORDING':
            this.startRecording(request.sessionId);
            this.broadcastToTabs({ action: 'START_RECORDING', sessionId: request.sessionId });
            sendResponse({ status: 'recording_started' });
            break;
  
          case 'STOP_RECORDING':
            this.stopRecording();
            this.broadcastToTabs({ action: 'STOP_RECORDING' });
            sendResponse({ status: 'recording_stopped' });
            break;
  
          case 'GET_STATUS':
            sendResponse({ 
              recording: this.recording,
              sessionId: this.sessionId,
              actionsCount: this.actions.length
            });
            break;
  
          case 'RECORD_ACTION':
            this.actions.push(request.data);
            // Store in local storage
            chrome.storage.local.set({ 
              [`action_${Date.now()}`]: request.data 
            });
            break;
  
          case 'PING':
            sendResponse({ connected: true, type: 'background' });
            break;
  
          default:
            sendResponse({ error: 'Unknown action' });
        }
        return true;
      });
  
      // Handle extension installation
      chrome.runtime.onInstalled.addListener(() => {
        console.log('🛡️ GeniusGuard extension installed');
      });
    }
  
    broadcastToTabs(message) {
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
          chrome.tabs.sendMessage(tab.id, message).catch(() => {
            // Tab might not have content script (e.g., chrome:// pages)
          });
        });
      });
    }
  
    startRecording(sessionId) {
      this.recording = true;
      this.sessionId = sessionId;
      this.actions = [];
      console.log('🎥 Background: Recording started for session', sessionId);
    }
  
    stopRecording() {
      this.recording = false;
      console.log('⏹️ Background: Recording stopped');
      
      // Send final batch of actions
      if (this.actions.length > 0) {
        this.sendBulkActions();
      }
    }
  
    sendBulkActions() {
      // This would send to your Django backend
      fetch('http://localhost:8000/api/deep/recorded-actions/bulk/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          session_id: this.sessionId,
          actions: this.actions
        })
      }).then(response => response.json())
        .then(data => console.log('📦 Background: Bulk actions sent:', data))
        .catch(console.error);
    }
  }
  
  // Initialize the background script
  const background = new GeniusGuardBackground();