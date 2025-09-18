// background.js - Basic Service Worker for Phishing Detection Extension
let settings = {
    autoScan: true,
    showNotifications: true,
    blockDangerous: true,
    sensitivity: 0.7,
    apiEndpoint: 'http://127.0.0.1:5000/predict'
};

let blockedSites = new Set();

// Initialize the background service
async function init() {
    try {
        await loadSettings();
        await loadBlockedSites();
        console.log('Phishing Detector Background Service initialized');
    } catch (error) {
        console.error('Initialization error:', error);
    }
}

// Load settings from storage
async function loadSettings() {
    try {
        const result = await chrome.storage.local.get(['settings']);
        if (result.settings) {
            settings = { ...settings, ...result.settings };
        }
    } catch (error) {
        console.error('Error loading settings:', error);
    }
}

// Load blocked sites from storage
async function loadBlockedSites() {
    try {
        const result = await chrome.storage.local.get(['blockedSites']);
        if (result.blockedSites) {
            blockedSites = new Set(result.blockedSites);
        }
    } catch (error) {
        console.error('Error loading blocked sites:', error);
    }
}

// Scan URL using backend API
async function scanUrl(url) {
    try {
        const response = await fetch(settings.apiEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url }),
            signal: AbortSignal.timeout(10000)
        });
        
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }
        
        const data = await response.json();
        
        // Update scan statistics
        await updateStats('urlsScanned', 1);
        
        return data;
        
    } catch (error) {
        console.error('Scan error:', error);
        return {
            is_phishing: false,
            confidence: 0.5,
            message: 'Unable to scan - server unavailable',
            error: true
        };
    }
}

// Update statistics
async function updateStats(key, increment = 1) {
    try {
        const result = await chrome.storage.local.get(['stats']);
        const stats = result.stats || { 
            urlsScanned: 0, 
            threatsBlocked: 0, 
            lastUpdate: new Date().toISOString() 
        };
        
        stats[key] = (stats[key] || 0) + increment;
        stats.lastUpdate = new Date().toISOString();
        
        await chrome.storage.local.set({ stats });
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}

// Handle extension messages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender, sendResponse);
    return true; // Will respond asynchronously
});

async function handleMessage(message, sender, sendResponse) {
    try {
        switch (message.type) {
            case 'scanUrl':
                const result = await scanUrl(message.url);
                sendResponse({ success: true, result });
                break;
                
            case 'getSettings':
                sendResponse({ success: true, settings });
                break;
                
            case 'updateSettings':
                settings = { ...settings, ...message.settings };
                await chrome.storage.local.set({ settings });
                sendResponse({ success: true });
                break;
                
            case 'blockSite':
                blockedSites.add(message.url);
                await chrome.storage.local.set({ 
                    blockedSites: Array.from(blockedSites) 
                });
                sendResponse({ success: true });
                break;
                
            case 'unblockSite':
                blockedSites.delete(message.url);
                await chrome.storage.local.set({ 
                    blockedSites: Array.from(blockedSites) 
                });
                sendResponse({ success: true });
                break;
                
            case 'getCurrentTabInfo':
                try {
                    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                    sendResponse({ 
                        success: true, 
                        tab: { url: tab.url, title: tab.title, id: tab.id }
                    });
                } catch (error) {
                    sendResponse({ success: false, error: 'Could not get tab info' });
                }
                break;
                
            default:
                sendResponse({ success: false, error: 'Unknown message type' });
        }
    } catch (error) {
        console.error('Message handling error:', error);
        sendResponse({ success: false, error: error.message });
    }
}

// Handle navigation events
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0 && settings.autoScan) {
        handleNavigation(details.url, details.tabId);
    }
});

async function handleNavigation(url, tabId) {
    if (!url || url.startsWith('chrome://') || url.startsWith('about:')) return;
    
    try {
        // Check if site is blocked
        if (isBlocked(url)) {
            chrome.tabs.update(tabId, { 
                url: chrome.runtime.getURL('blocked.html') + 
                     `?url=${encodeURIComponent(url)}&message=${encodeURIComponent('This site has been blocked for your protection.')}`
            });
            return;
        }
        
        // Scan the URL if auto-scan is enabled
        if (settings.autoScan) {
            const scanResult = await scanUrl(url);
            if (scanResult && scanResult.is_phishing && scanResult.confidence >= settings.sensitivity) {
                if (settings.blockDangerous && scanResult.confidence >= 0.8) {
                    // Block high confidence threats
                    chrome.tabs.update(tabId, { 
                        url: chrome.runtime.getURL('blocked.html') + 
                             `?url=${encodeURIComponent(url)}&message=${encodeURIComponent(scanResult.message)}`
                    });
                    await updateStats('threatsBlocked', 1);
                } else if (settings.showNotifications) {
                    // Show notification for medium threats
                    chrome.notifications.create({
                        type: 'basic',
                        iconUrl: 'icons/icon48.png',
                        title: 'Phishing Warning',
                        message: `Suspicious site detected: ${new URL(url).hostname}`
                    });
                }
            }
        }
        
    } catch (error) {
        console.error('Navigation handling error:', error);
    }
}

function isBlocked(url) {
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        return blockedSites.has(url) || blockedSites.has(domain);
    } catch {
        return false;
    }
}

// Handle installation
chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: 'Phishing Detector Installed',
            message: 'You are now protected from phishing attacks!'
        });
    }
});

// Initialize
init();