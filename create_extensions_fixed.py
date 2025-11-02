import os
import json
import shutil

def create_chrome_extension():
    print("Creating Chrome extension...")
    
    ext_dir = 'static/downloads/GG-extension-chrome'
    os.makedirs(ext_dir, exist_ok=True)
    os.makedirs(f'{ext_dir}/icons', exist_ok=True)
    
    # Chrome manifest
    chrome_manifest = {
        "manifest_version": 3,
        "name": "GG Security Recorder",
        "version": "1.0.0",
        "description": "Record user sessions for security vulnerability analysis",
        "permissions": [
            "activeTab",
            "storage",
            "scripting"
        ],
        "host_permissions": [
            "http://*/*",
            "https://*/*"
        ],
        "background": {
            "service_worker": "background.js"
        },
        "content_scripts": [
            {
                "matches": ["http://*/*", "https://*/*"],
                "js": ["content.js"],
                "run_at": "document_end"
            }
        ],
        "action": {
            "default_popup": "popup.html",
            "default_title": "GG Security Recorder"
        },
        "icons": {
            "16": "icons/icon16.png",
            "48": "icons/icon48.png",
            "128": "icons/icon128.png"
        }
    }
    
    # Write manifest
    with open(f'{ext_dir}/manifest.json', 'w') as f:
        json.dump(chrome_manifest, f, indent=2)
    
    # Write background.js
    with open(f'{ext_dir}/background.js', 'w') as f:
        f.write("""let recordingSessions = new Map();
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
}""")
    
    # Write content.js
    with open(f'{ext_dir}/content.js', 'w') as f:
        f.write("""let isRecording = false;
let currentSessionId = null;

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log('Content script received:', request.action);
    
    switch (request.action) {
        case 'startRecording':
            isRecording = true;
            currentSessionId = request.sessionId;
            startEventListeners();
            sendResponse({ status: 'recording_started' });
            break;
        case 'stopRecording':
            isRecording = false;
            currentSessionId = null;
            stopEventListeners();
            sendResponse({ status: 'recording_stopped' });
            break;
        case 'ping':
            sendResponse({ status: 'alive', recording: isRecording });
            break;
    }
    return true;
});

function startEventListeners() {
    document.addEventListener('click', handleClick, true);
    document.addEventListener('input', handleInput, true);
    document.addEventListener('submit', handleSubmit, true);
    document.addEventListener('change', handleChange, true);
    console.log('Event listeners started');
}

function stopEventListeners() {
    document.removeEventListener('click', handleClick, true);
    document.removeEventListener('input', handleInput, true);
    document.removeEventListener('submit', handleSubmit, true);
    document.removeEventListener('change', handleChange, true);
    console.log('Event listeners stopped');
}

function handleClick(event) {
    if (!isRecording) return;
    
    const target = event.target;
    const action = {
        action_type: 'click',
        target_element: getElementDescription(target),
        target_selector: getElementSelector(target),
        url: window.location.href,
        timestamp: Date.now(),
        dom_snapshot: getElementSnapshot(target)
    };
    
    recordAction(action);
}

function handleInput(event) {
    if (!isRecording) return;
    
    const target = event.target;
    const value = target.type === 'password' ? '***' : target.value;
    const action = {
        action_type: 'input',
        target_element: getElementDescription(target),
        target_selector: getElementSelector(target),
        value: value,
        url: window.location.href,
        timestamp: Date.now(),
        dom_snapshot: getElementSnapshot(target)
    };
    
    recordAction(action);
}

function handleSubmit(event) {
    if (!isRecording) return;
    
    const target = event.target;
    const action = {
        action_type: 'submit',
        target_element: getElementDescription(target),
        target_selector: getElementSelector(target),
        url: window.location.href,
        timestamp: Date.now(),
        dom_snapshot: getFormSnapshot(target)
    };
    
    recordAction(action);
}

function handleChange(event) {
    if (!isRecording) return;
    
    const target = event.target;
    if (target.type === 'checkbox' || target.type === 'radio' || target.tagName === 'SELECT') {
        const action = {
            action_type: 'change',
            target_element: getElementDescription(target),
            target_selector: getElementSelector(target),
            value: target.type === 'checkbox' ? target.checked : target.value,
            url: window.location.href,
            timestamp: Date.now(),
            dom_snapshot: getElementSnapshot(target)
        };
        
        recordAction(action);
    }
}

function getElementDescription(element) {
    if (element.id) return '#' + element.id;
    if (element.name) return '[name="' + element.name + '"]';
    if (element.className && typeof element.className === 'string') {
        return '.' + element.className.split(' ')[0];
    }
    return element.tagName ? element.tagName.toLowerCase() : 'unknown';
}

function getElementSelector(element) {
    if (!element.tagName) return 'unknown';
    
    let selector = element.tagName.toLowerCase();
    if (element.id) {
        selector += '#' + element.id;
    }
    if (element.className && typeof element.className === 'string') {
        selector += '.' + element.className.split(' ').join('.');
    }
    
    return selector;
}

function getElementSnapshot(element) {
    return {
        tagName: element.tagName || 'unknown',
        id: element.id || '',
        className: element.className || '',
        name: element.name || '',
        type: element.type || '',
        value: element.type === 'password' ? '***' : (element.value || ''),
        checked: element.checked || false,
        placeholder: element.placeholder || '',
        innerText: element.innerText ? element.innerText.substring(0, 100) : ''
    };
}

function getFormSnapshot(form) {
    const inputs = Array.from(form.elements || []).map(element => ({
        name: element.name || '',
        type: element.type || '',
        value: element.type === 'password' ? '***' : (element.value || '')
    }));
    
    return {
        action: form.action || '',
        method: form.method || '',
        inputs: inputs
    };
}

function recordAction(action) {
    chrome.runtime.sendMessage({
        action: 'recordAction',
        data: action
    }).catch(err => {
        console.log('Could not send action:', err);
    });
}

// Check initial status
chrome.runtime.sendMessage({ action: 'getRecordingStatus' }, (response) => {
    if (response && response.isRecording) {
        isRecording = true;
        currentSessionId = response.sessionId;
        startEventListeners();
    }
});""")
    
    # Write popup.html
    with open(f'{ext_dir}/popup.html', 'w') as f:
        f.write("""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { width: 320px; padding: 16px; font-family: Arial, sans-serif; background: #1a1a1a; color: white; margin: 0; }
        .status { padding: 12px; border-radius: 6px; margin-bottom: 12px; text-align: center; font-weight: bold; border: 1px solid; }
        .recording { background: #d4edda; color: #155724; border-color: #155724; }
        .stopped { background: #f8d7da; color: #721c24; border-color: #721c24; }
        .connected { background: #d1ecf1; color: #0c5460; border-color: #0c5460; }
        button { width: 100%; padding: 10px; margin: 6px 0; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .btn-start { background: #28a745; color: white; }
        .btn-stop { background: #dc3545; color: white; }
        .btn-auth { background: #007bff; color: white; }
        input { width: 100%; padding: 8px; margin: 4px 0; border: 1px solid #555; border-radius: 4px; background: #2a2a2a; color: white; box-sizing: border-box; }
        .section { margin: 12px 0; padding: 12px; background: rgba(255,255,255,0.1); border-radius: 6px; }
    </style>
</head>
<body>
    <div style="text-align: center; margin-bottom: 16px;">
        <h3 style="margin: 0; color: #00f0ff;">🛡️ GG Security</h3>
    </div>
    
    <div id="status" class="status stopped">Not Connected</div>
    
    <div class="section">
        <h4 style="margin: 0 0 8px 0;">Authentication</h4>
        <input type="text" id="backend-url" placeholder="Backend URL" value="http://localhost:8000">
        <input type="text" id="auth-token" placeholder="Enter auth token">
        <button id="save-settings" class="btn-auth">Save Settings</button>
    </div>
    
    <div class="section">
        <button id="start-recording" class="btn-start">Start Recording</button>
        <button id="stop-recording" class="btn-stop" disabled>Stop Recording</button>
    </div>
    
    <script src="popup.js"></script>
</body>
</html>""")
    
    # Write popup.js
    with open(f'{ext_dir}/popup.js', 'w') as f:
        f.write("""document.addEventListener('DOMContentLoaded', () => {
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
});""")
    
    # Create simple SVG icons
    create_svg_icon(f'{ext_dir}/icons/icon16.png', 16)
    create_svg_icon(f'{ext_dir}/icons/icon48.png', 48)
    create_svg_icon(f'{ext_dir}/icons/icon128.png', 128)
    
    print("Chrome extension created!")

def create_firefox_extension():
    print("Creating Firefox extension...")
    
    ext_dir = 'static/downloads/GG-extension-firefox'
    os.makedirs(ext_dir, exist_ok=True)
    os.makedirs(f'{ext_dir}/icons', exist_ok=True)
    
    # Firefox manifest
    firefox_manifest = {
        "manifest_version": 2,
        "name": "GG Security Recorder",
        "version": "1.0.0",
        "description": "Record user sessions for security vulnerability analysis",
        "permissions": [
            "activeTab",
            "storage",
            "http://*/*",
            "https://*/*"
        ],
        "background": {
            "scripts": ["background.js"],
            "persistent": False
        },
        "content_scripts": [
            {
                "matches": ["http://*/*", "https://*/*"],
                "js": ["content.js"],
                "run_at": "document_end"
            }
        ],
        "browser_action": {
            "default_popup": "popup.html",
            "default_title": "GG Security Recorder"
        },
        "icons": {
            "16": "icons/icon16.png",
            "48": "icons/icon48.png",
            "128": "icons/icon128.png"
        }
    }
    
    # Write manifest
    with open(f'{ext_dir}/manifest.json', 'w') as f:
        json.dump(firefox_manifest, f, indent=2)
    
    # Copy all other files from Chrome extension
    for file in ['background.js', 'content.js', 'popup.html', 'popup.js']:
        shutil.copy2(f'static/downloads/GG-extension-chrome/{file}', f'{ext_dir}/{file}')
    
    # Copy icons
    for icon in ['icon16.png', 'icon48.png', 'icon128.png']:
        shutil.copy2(f'static/downloads/GG-extension-chrome/icons/{icon}', f'{ext_dir}/icons/{icon}')
    
    print("Firefox extension created!")

def create_edge_extension():
    print("Creating Edge extension...")
    
    ext_dir = 'static/downloads/GG-extension-edge'
    shutil.copytree('static/downloads/GG-extension-chrome', ext_dir)
    print("Edge extension created!")

def create_svg_icon(filename, size):
    """Create a simple SVG icon"""
    svg_content = f'''<svg width="{size}" height="{size}" xmlns="http://www.w3.org/2000/svg">
        <rect width="100%" height="100%" fill="#00f0ff"/>
        <rect x="2" y="2" width="{size-4}" height="{size-4}" fill="white" opacity="0.2"/>
        <text x="50%" y="50%" font-family="Arial" font-size="{size//4}" fill="white" text-anchor="middle" dy=".3em">S</text>
    </svg>'''
    
    with open(filename, 'w') as f:
        f.write(svg_content)

if __name__ == '__main__':
    print("Creating proper browser extension directories...")
    create_chrome_extension()
    create_firefox_extension()
    create_edge_extension()
    print("All extension directories created successfully!")
    print("\\nInstallation Instructions:")
    print("1. Enable Developer Mode in your browser")
    print("2. Load the extension as an unpacked extension")
    print("3. Select the appropriate extension folder")