const chatMessages = document.getElementById('chat-messages');
const chatInput = document.getElementById('chat-input');
let fontSize = 14;

if (/Mobi|Android/i.test(navigator.userAgent)) {
    fontSize = 12;
}

chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

function addMessage(content, role) {
    const messageDiv = document.createElement('div');
    messageDiv.classList.add('chat-message', role);

    const bubble = document.createElement('div');
    bubble.classList.add('chat-bubble', role);
    bubble.innerHTML = formatMessage(content);
    bubble.style.fontSize = fontSize + 'px';

    messageDiv.appendChild(bubble);
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function formatMessage(text) {
    // Basic markdown formatting
    text = text.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
    text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
    text = text.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    text = text.replace(/\n/g, '<br>');
    return text;
}

function showTypingIndicator() {
    const indicator = document.createElement('div');
    indicator.classList.add('chat-message', 'assistant');
    indicator.id = 'typing-indicator';

    const bubble = document.createElement('div');
    bubble.classList.add('chat-bubble', 'assistant', 'typing');
    bubble.innerHTML = '<span class="dot"></span><span class="dot"></span><span class="dot"></span>';

    indicator.appendChild(bubble);
    chatMessages.appendChild(indicator);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function removeTypingIndicator() {
    const indicator = document.getElementById('typing-indicator');
    if (indicator) indicator.remove();
}

function sendMessage() {
    const message = chatInput.value.trim();
    if (!message) return;

    addMessage(message, 'user');
    chatInput.value = '';
    chatInput.disabled = true;
    document.getElementById('chat-send').disabled = true;
    showTypingIndicator();

    fetch('/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: message })
    })
    .then(response => response.json())
    .then(data => {
        removeTypingIndicator();
        chatInput.disabled = false;
        document.getElementById('chat-send').disabled = false;
        chatInput.focus();

        if (data.error) {
            addMessage('Error: ' + data.error, 'error');
        } else {
            addMessage(data.response, 'assistant');
        }
    })
    .catch(error => {
        removeTypingIndicator();
        chatInput.disabled = false;
        document.getElementById('chat-send').disabled = false;
        chatInput.focus();
        addMessage('Connection error: ' + error.message, 'error');
    });
}

function clearChat() {
    chatMessages.innerHTML = '';
    fetch('/chat_clear', { method: 'POST' })
        .then(response => response.json())
        .then(() => {
            addMessage("Conversation cleared. How can I help?", 'assistant');
        })
        .catch(error => console.error('Error clearing chat:', error));
}

// Welcome message on load
document.addEventListener('DOMContentLoaded', () => {
    addMessage(
        "I am Bjorn's AI assistant. Ask me about the network, targets, credentials, or tell me to execute actions.",
        'assistant'
    );
});
