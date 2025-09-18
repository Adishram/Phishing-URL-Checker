// settings.js - Basic Settings Page Functionality
document.addEventListener('DOMContentLoaded', () => {
    loadSettings();
    setupEventListeners();
});

let settings = {
    autoScan: true,
    showNotifications: true,
    blockDangerous: true,
    sensitivity: 0.7,
    apiEndpoint: 'http://127.0.0.1:5000/predict'
};

async function loadSettings() {
    try {
        const result = await chrome.storage.local.get(['settings']);
        if (result.settings) {
            settings = { ...settings, ...result.settings };
        }
        updateUI();
    } catch (error) {
        console.error('Error loading settings:', error);
    }
}

function updateUI() {
    // Update toggles
    document.getElementById('auto-scan-toggle').classList.toggle('active', settings.autoScan);
    document.getElementById('notifications-toggle').classList.toggle('active', settings.showNotifications);
    document.getElementById('auto-block-toggle').classList.toggle('active', settings.blockDangerous);
    
    // Update sensitivity
    const slider = document.getElementById('sensitivity-slider');
    const value = document.getElementById('sensitivity-value');
    if (slider && value) {
        slider.value = settings.sensitivity;
        value.textContent = Math.round(settings.sensitivity * 100) + '%';
    }
    
    // Update API endpoint
    const apiInput = document.getElementById('api-endpoint');
    if (apiInput) {
        apiInput.value = settings.apiEndpoint;
    }
}

function setupEventListeners() {
    // Toggle switches
    setupToggle('auto-scan-toggle', 'autoScan');
    setupToggle('notifications-toggle', 'showNotifications');
    setupToggle('auto-block-toggle', 'blockDangerous');
    
    // Sensitivity slider
    const slider = document.getElementById('sensitivity-slider');
    if (slider) {
        slider.addEventListener('input', (e) => {
            const value = parseFloat(e.target.value);
            settings.sensitivity = value;
            document.getElementById('sensitivity-value').textContent = Math.round(value * 100) + '%';
        });
    }
    
    // API endpoint
    const apiInput = document.getElementById('api-endpoint');
    if (apiInput) {
        apiInput.addEventListener('blur', (e) => {
            settings.apiEndpoint = e.target.value || 'http://127.0.0.1:5000/predict';
        });
    }
    
    // Save button
    const saveBtn = document.getElementById('save-settings');
    if (saveBtn) {
        saveBtn.addEventListener('click', saveSettings);
    }
    
    // Reset button
    const resetBtn = document.getElementById('reset-settings');
    if (resetBtn) {
        resetBtn.addEventListener('click', resetSettings);
    }
}

function setupToggle(toggleId, settingKey) {
    const toggle = document.getElementById(toggleId);
    if (toggle) {
        toggle.addEventListener('click', () => {
            settings[settingKey] = !settings[settingKey];
            toggle.classList.toggle('active', settings[settingKey]);
        });
    }
}

async function saveSettings() {
    try {
        await chrome.storage.local.set({ settings });
        
        // Notify background script
        chrome.runtime.sendMessage({
            type: 'updateSettings',
            settings: settings
        });
        
        showMessage('Settings saved successfully', 'success');
    } catch (error) {
        console.error('Error saving settings:', error);
        showMessage('Failed to save settings', 'error');
    }
}

function resetSettings() {
    if (confirm('Are you sure you want to reset all settings to defaults?')) {
        settings = {
            autoScan: true,
            showNotifications: true,
            blockDangerous: true,
            sensitivity: 0.7,
            apiEndpoint: 'http://127.0.0.1:5000/predict'
        };
        updateUI();
        saveSettings();
    }
}

function showMessage(message, type) {
    const messageEl = document.getElementById(type + '-message');
    if (messageEl) {
        messageEl.textContent = message;
        messageEl.style.display = 'block';
        
        setTimeout(() => {
            messageEl.style.display = 'none';
        }, 3000);
    } else {
        alert(message);
    }
}