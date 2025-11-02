let recordingSessions = new Map();
let currentSession = null;

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log('Background received:', request.action);
    
    switch (request.action) {
        case 'startRecording':
            startRecording(request.sessionId);
            sendResponse({ status: 'recording_started' });
            break;
        case 'stopRecording':
            stopRecording();
            sendResponse({ status: 'recording_stopped' });
            break;
        case 'getRecordingStatus':
            sendResponse({ 
                isRecording: currentSession !== null,
                sessionId: currentSession 
            });
            break;
        case 'recordAction':
            if (currentSession) recordAction(request.data);
            break;
        case 'checkConnection':
            sendResponse({ status: 'connected', version: '1.0.0' });
            break;
    }
    return true;
});

function startRecording(sessionId) {
    currentSession = sessionId;
    recordingSessions.set(sessionId, {
        startTime: Date.now(),
        actions: [],
        metadata: { 
            userAgent: navigator.userAgent, 
            platform: navigator.platform,
            timestamp: new Date().toISOString()
        }
    });
    
    chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
            chrome.tabs.sendMessage(tab.id, { 
                action: 'startRecording', 
                sessionId: sessionId 
            }).catch(err => {
                console.log('Tab not ready:', tab.id);
            });
        });
    });
}

function stopRecording() {
    if (currentSession) {
        const session = recordingSessions.get(currentSession);
        if (session) {
            sendRecordedData(session);
        }
        recordingSessions.delete(currentSession);
        currentSession = null;
    }
    
    chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
            chrome.tabs.sendMessage(tab.id, { 
                action: 'stopRecording' 
            }).catch(err => {
                console.log('Tab not ready:', tab.id);
            });
        });
    });
}

function recordAction(actionData) {
    if (currentSession) {
        const session = recordingSessions.get(currentSession);
        if (session) {
            session.actions.push({
                ...actionData,
                absoluteTimestamp: Date.now(),
                relativeTimestamp: Date.now() - session.startTime
            });
        }
    }
}

async function sendRecordedData(session) {
    try {
        const authToken = await getAuthToken();
        if (!authToken) {
            console.error('No auth token available');
            return;
        }

        const response = await fetch('http://localhost:8000/api/deep/recorded-actions/bulk/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + authToken
            },
            body: JSON.stringify({
                session_id: currentSession,
                actions: session.actions,
                metadata: session.metadata
            })
        });
        
        if (response.ok) {
            console.log('Data sent successfully:', session.actions.length, 'actions');
        } else {
            console.error('Failed to send data:', response.status);
        }
    } catch (error) {
        console.error('Error sending recorded data:', error);
    }
}

async function getAuthToken() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['authToken'], (result) => {
            resolve(result.authToken);
        });
    });
}