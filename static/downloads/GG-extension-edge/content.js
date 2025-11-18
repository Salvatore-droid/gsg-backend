// Content script to record user actions
let isRecording = false;
let currentSessionId = null;

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Content script received:', request);
  
  switch (request.action) {
    case 'START_RECORDING':
      isRecording = true;
      currentSessionId = request.sessionId;
      startActionRecording();
      sendResponse({ status: 'recording_started' });
      break;
      
    case 'STOP_RECORDING':
      isRecording = false;
      currentSessionId = null;
      stopActionRecording();
      sendResponse({ status: 'recording_stopped' });
      break;
      
    case 'PING':
      sendResponse({ connected: true });
      break;
  }
  
  return true;
});

function startActionRecording() {
  console.log('Starting action recording on:', window.location.href);
  
  // Record clicks
  document.addEventListener('click', recordClick, true);
  
  // Record form inputs
  document.addEventListener('input', recordInput, true);
  
  // Record form submissions
  document.addEventListener('submit', recordFormSubmit, true);
  
  // Record navigation
  window.addEventListener('beforeunload', recordNavigation);
  
  // Record page load
  recordPageLoad();
}

function stopActionRecording() {
  console.log('Stopping action recording');
  
  document.removeEventListener('click', recordClick, true);
  document.removeEventListener('input', recordInput, true);
  document.removeEventListener('submit', recordFormSubmit, true);
  window.removeEventListener('beforeunload', recordNavigation);
}

function recordClick(event) {
  if (!isRecording) return;
  
  const target = event.target;
  const actionData = {
    action_type: 'click',
    target_element: getElementDescription(target),
    target_selector: getElementSelector(target),
    url: window.location.href,
    timestamp: Date.now(),
    value: target.value || target.textContent || '',
    dom_snapshot: {
      tag_name: target.tagName,
      classes: target.className,
      id: target.id,
      attributes: getElementAttributes(target)
    }
  };
  
  console.log('Recording click:', actionData);
  sendActionToBackground(actionData);
}

function recordInput(event) {
  if (!isRecording) return;
  
  const target = event.target;
  const actionData = {
    action_type: 'input',
    target_element: getElementDescription(target),
    target_selector: getElementSelector(target),
    url: window.location.href,
    timestamp: Date.now(),
    value: target.value,
    dom_snapshot: {
      tag_name: target.tagName,
      type: target.type,
      name: target.name,
      classes: target.className,
      id: target.id
    }
  };
  
  console.log('Recording input:', actionData);
  sendActionToBackground(actionData);
}

function recordFormSubmit(event) {
  if (!isRecording) return;
  
  const target = event.target;
  const actionData = {
    action_type: 'submit',
    target_element: getElementDescription(target),
    target_selector: getElementSelector(target),
    url: window.location.href,
    timestamp: Date.now(),
    value: '',
    dom_snapshot: {
      tag_name: target.tagName,
      classes: target.className,
      id: target.id
    }
  };
  
  console.log('Recording form submit:', actionData);
  sendActionToBackground(actionData);
}

function recordNavigation() {
  if (!isRecording) return;
  
  const actionData = {
    action_type: 'navigation',
    target_element: 'Page Navigation',
    target_selector: 'window',
    url: window.location.href,
    timestamp: Date.now(),
    value: 'Page unload',
    dom_snapshot: {}
  };
  
  console.log('Recording navigation:', actionData);
  sendActionToBackground(actionData);
}

function recordPageLoad() {
  if (!isRecording) return;
  
  const actionData = {
    action_type: 'navigation',
    target_element: 'Page Load',
    target_selector: 'window',
    url: window.location.href,
    timestamp: Date.now(),
    value: 'Page loaded: ' + document.title,
    dom_snapshot: {
      title: document.title,
      url: window.location.href
    }
  };
  
  console.log('Recording page load:', actionData);
  sendActionToBackground(actionData);
}

function getElementDescription(element) {
  if (element.id) return `#${element.id}`;
  if (element.name) return `[name="${element.name}"]`;
  if (element.type) return `input[type="${element.type}"]`;
  if (element.tagName) return element.tagName.toLowerCase();
  return 'unknown';
}

function getElementSelector(element) {
  if (element.id) return `#${element.id}`;
  
  let selector = element.tagName.toLowerCase();
  if (element.className && typeof element.className === 'string') {
    selector += '.' + element.className.split(' ').join('.');
  }
  
  return selector;
}

function getElementAttributes(element) {
  const attributes = {};
  for (let attr of element.attributes) {
    attributes[attr.name] = attr.value;
  }
  return attributes;
}

function sendActionToBackground(actionData) {
  chrome.runtime.sendMessage({
    action: 'RECORD_ACTION',
    actionData: actionData
  }).catch(err => {
    console.log('Could not send action to background:', err);
  });
}