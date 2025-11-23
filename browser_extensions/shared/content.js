// Content script - runs on every page
class GeniusGuardRecorder {
    constructor() {
      this.recording = false;
      this.sessionId = null;
      this.actions = [];
      this.init();
    }
  
    init() {
      // Listen for messages from background script
      chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === 'START_RECORDING') {
          this.startRecording(request.sessionId);
          sendResponse({ status: 'recording_started' });
        } else if (request.action === 'STOP_RECORDING') {
          this.stopRecording();
          sendResponse({ status: 'recording_stopped' });
        } else if (request.action === 'GET_STATUS') {
          sendResponse({ 
            recording: this.recording,
            sessionId: this.sessionId,
            actionsCount: this.actions.length
          });
        } else if (request.action === 'PING') {
          sendResponse({ connected: true, type: 'content_script' });
        }
        return true;
      });
  
      this.setupEventListeners();
    }
  
    setupEventListeners() {
      // Track clicks
      document.addEventListener('click', (e) => {
        if (!this.recording) return;
        
        this.recordAction('click', {
          target: e.target.tagName,
          text: e.target.textContent?.substring(0, 100),
          href: e.target.href,
          selector: this.getSelector(e.target)
        });
      });
  
      // Track form inputs
      document.addEventListener('input', (e) => {
        if (!this.recording) return;
        
        this.recordAction('input', {
          target: e.target.tagName,
          type: e.target.type,
          name: e.target.name,
          value: e.target.value?.substring(0, 200),
          selector: this.getSelector(e.target)
        });
      });
  
      // Track form submissions
      document.addEventListener('submit', (e) => {
        if (!this.recording) return;
        
        this.recordAction('submit', {
          target: 'FORM',
          action: e.target.action,
          method: e.target.method,
          selector: this.getSelector(e.target)
        });
      });
  
      // Track page navigation
      window.addEventListener('beforeunload', () => {
        if (!this.recording) return;
        
        this.recordAction('navigation', {
          from: document.location.href,
          to: 'next_page'
        });
      });
    }
  
    getSelector(element) {
      if (element.id) return `#${element.id}`;
      if (element.className) return `.${element.className.split(' ')[0]}`;
      return element.tagName;
    }
  
    recordAction(type, data) {
      const action = {
        action_type: type,
        target_element: data.target,
        target_selector: data.selector,
        value: data.value || data.text,
        url: document.location.href,
        timestamp: Date.now(),
        ...data
      };
  
      this.actions.push(action);
      
      // Send to background script for storage
      chrome.runtime.sendMessage({
        action: 'RECORD_ACTION',
        data: action
      });
  
      // Also send to the dashboard if on the same origin
      if (document.location.origin === 'http://localhost:5173') {
        this.sendToDashboard(action);
      }
    }
  
    sendToDashboard(action) {
      fetch('http://localhost:5173/api/deep/actions/record/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...action,
          session_id: this.sessionId
        })
      }).catch(console.error);
    }
  
    startRecording(sessionId) {
      this.recording = true;
      this.sessionId = sessionId;
      this.actions = [];
      console.log('🎥 GeniusGuard recording started');
    }
  
    stopRecording() {
      this.recording = false;
      console.log('⏹️ GeniusGuard recording stopped');
      
      // Send all recorded actions to the dashboard
      if (this.actions.length > 0) {
        this.sendBulkActions();
      }
    }
  
    sendBulkActions() {
      fetch('http://localhost:5173/api/deep/recorded-actions/bulk/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          session_id: this.sessionId,
          actions: this.actions
        })
      }).then(response => response.json())
        .then(data => console.log('📦 Bulk actions sent:', data))
        .catch(console.error);
    }
  }
  
  // Initialize the recorder
  const recorder = new GeniusGuardRecorder();