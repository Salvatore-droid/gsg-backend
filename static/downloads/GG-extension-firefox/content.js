let isRecording = false;
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
});