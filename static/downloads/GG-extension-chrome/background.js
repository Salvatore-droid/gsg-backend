// Background script for GENIUSGAURD extension
let currentSession = null;
let isRecording = false;

// Handle extension installation
chrome.runtime.onInstalled.addListener(() => {
  console.log('GENIUSGAURD Security Extension installed');
});

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Background received message:', request);
  
  switch (request.action) {
    case 'PING':
      sendResponse({ connected: true, version: '1.0.0' });
      break;
      
    case 'START_RECORDING':
      startRecording(request.sessionId);
      sendResponse({ status: 'recording_started', sessionId: request.sessionId });
      break;
      
    case 'STOP_RECORDING':
      stopRecording();
      sendResponse({ status: 'recording_stopped' });
      break;
      
    case 'GET_STATUS':
      sendResponse({ 
        isRecording, 
        sessionId: currentSession,
        connected: true,
        version: '1.0.0'
      });
      break;
      
    case 'RECORD_ACTION':
      if (isRecording && currentSession) {
        recordActionToBackend(request.actionData);
      }
      sendResponse({ status: 'action_received' });
      break;
  }
  
  return true; // Keep message channel open for async responses
});

function startRecording(sessionId) {
  console.log('Starting recording for session:', sessionId);
  currentSession = sessionId;
  isRecording = true;
  
  // Notify all tabs to start recording
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      chrome.tabs.sendMessage(tab.id, {
        action: 'START_RECORDING',
        sessionId: sessionId
      }).catch(err => {
        console.log('Could not notify tab:', tab.id, err);
      });
    });
  });
}

function stopRecording() {
  console.log('Stopping recording');
  isRecording = false;
  currentSession = null;
  
  // Notify all tabs to stop recording
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      chrome.tabs.sendMessage(tab.id, {
        action: 'STOP_RECORDING'
      }).catch(err => {
        console.log('Could not notify tab:', tab.id, err);
      });
    });
  });
}

async function recordActionToBackend(actionData) {
  try {
    console.log('Recording action:', actionData.action_type);
    
    const response = await fetch('http://localhost:8000/api/deep/recorded-actions/bulk/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        session_id: currentSession,
        actions: [actionData],
        metadata: {
          user_agent: navigator.userAgent,
          timestamp: new Date().toISOString(),
          extension_version: '1.0.0'
        }
      })
    });
    
    if (!response.ok) {
      console.error('Failed to record action:', await response.text());
    } else {
      console.log('Action recorded successfully');
    }
  } catch (error) {
    console.error('Error recording action:', error);
  }
}