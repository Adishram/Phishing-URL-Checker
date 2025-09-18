// popup.js - Functional Extension Popup with Working Buttons
class ExtensionPopup {
    constructor() {
        this.apiUrl = 'http://127.0.0.1:5000/predict';
        this.isScanning = false;
        this.stats = {
            urlsScanned: 0,
            threatsBlocked: 0,
            lastUpdate: new Date()
        };
        
        this.init();
    }
    
    async init() {
        await this.loadStats();
        await this.checkCurrentSite();
        this.setupEventListeners();
        this.updateStatsDisplay();
    }
    
    async loadStats() {
        try {
            const result = await chrome.storage.local.get(['stats']);
            if (result.stats) {
                this.stats = { ...this.stats, ...result.stats };
            }
        } catch (error) {
            console.log('Error loading stats:', error);
        }
    }
    
    async saveStats() {
        try {
            await chrome.storage.local.set({ stats: this.stats });
        } catch (error) {
            console.log('Error saving stats:', error);
        }
    }
    
    async checkCurrentSite() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab || !tab.url) {
                this.updateCurrentSiteDisplay('No active tab', 'Unknown', 'safe', 0.5);
                return;
            }
            
            const url = tab.url;
            document.getElementById('site-url').textContent = this.truncateUrl(url);
            
            if (url.startsWith('chrome://') || url.startsWith('about:')) {
                this.updateCurrentSiteDisplay('Chrome System Page', 'System page - no scan needed', 'safe', 1.0);
                return;
            }
            
            this.updateCurrentSiteDisplay('Analyzing...', 'Checking site safety...', 'safe', 0.5);
            
            const result = await this.scanUrl(url, false);
            if (result) {
                const status = result.is_phishing ? 'danger' : 'safe';
                const title = result.is_phishing ? 'Potential Threat Detected' : 'Site Appears Safe';
                const confidence = `${Math.round(result.confidence * 100)}% confidence`;
                
                this.updateCurrentSiteDisplay(title, confidence, status, result.confidence);
            } else {
                this.updateCurrentSiteDisplay('Scan Failed', 'Could not analyze site', 'warning', 0.5);
            }
            
        } catch (error) {
            console.error('Error checking current site:', error);
            this.updateCurrentSiteDisplay('Error', 'Unable to check site', 'warning', 0.5);
        }
    }
    
    updateCurrentSiteDisplay(title, subtitle, status, confidence) {
        const statusIndicator = document.getElementById('status-indicator');
        const siteTitle = document.getElementById('site-title');
        const siteConfidence = document.getElementById('site-confidence');
        
        statusIndicator.className = `status-indicator status-${status}`;
        statusIndicator.textContent = status === 'safe' ? '✓' : status === 'warning' ? '!' : '⚠';
        
        siteTitle.textContent = title;
        siteConfidence.textContent = subtitle;
    }
    
    setupEventListeners() {
        // Scan button
        const scanButton = document.getElementById('scan-button');
        const urlInput = document.getElementById('url-input');
        
        scanButton.addEventListener('click', () => this.handleScan());
        urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !this.isScanning) {
                this.handleScan();
            }
        });
        
        // Settings button - Show settings modal
        document.getElementById('settings-btn').addEventListener('click', () => {
            this.showSettings();
        });
        
        // History button - Show scan history
        document.getElementById('history-btn').addEventListener('click', () => {
            this.showHistory();
        });
        
        // Help button - Show help information
        document.getElementById('help-btn').addEventListener('click', () => {
            this.showHelp();
        });
    }
    
    async handleScan() {
        const urlInput = document.getElementById('url-input');
        const url = urlInput.value.trim();
        
        if (!url) {
            this.showError('Please enter a URL to scan');
            return;
        }
        
        const fullUrl = url.startsWith('http') ? url : `https://${url}`;
        
        this.showLoading();
        const result = await this.scanUrl(fullUrl, true);
        this.hideLoading();
        
        if (result) {
            this.showScanResult(result);
            this.stats.urlsScanned++;
            if (result.is_phishing) {
                this.stats.threatsBlocked++;
            }
            this.stats.lastUpdate = new Date();
            await this.saveStats();
            this.updateStatsDisplay();
            
            // Save to scan history
            await this.saveScanToHistory(fullUrl, result);
        }
    }
    
    async scanUrl(url, updateStats = false) {
        console.log('Attempting to scan URL:', url);
        console.log('API endpoint:', this.apiUrl);
        
        try {
            const response = await fetch(this.apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url })
            });
            
            console.log('Response status:', response.status);
            console.log('Response ok:', response.ok);
            
            if (!response.ok) {
                throw new Error(`Server returned ${response.status}`);
            }
            
            const data = await response.json();
            console.log('Response data:', data);
            return data;
            
        } catch (error) {
            console.error('Detailed scan error:', error);
            this.showError('Unable to scan URL. Make sure the backend is running on port 5000.');
            return null;
        }
    }
    
    showScanResult(result) {
        const resultContainer = document.getElementById('scan-result');
        const errorContainer = document.getElementById('error-message');
        
        errorContainer.innerHTML = '';
        
        const resultType = result.is_phishing ? 
            (result.confidence > 0.8 ? 'danger' : 'warning') : 'safe';
        
        const icon = result.is_phishing ? 
            (result.confidence > 0.8 ? '⚠️' : '⚡') : '✅';
        
        resultContainer.innerHTML = `
            <div class="scan-result ${resultType}">
                <div class="result-header">
                    <div class="result-icon">${icon}</div>
                    <div class="result-title">
                        ${result.is_phishing ? 
                            (result.confidence > 0.8 ? 'Phishing Detected!' : 'Suspicious URL') : 
                            'URL is Safe'}
                    </div>
                    <div class="result-confidence">${Math.round(result.confidence * 100)}%</div>
                </div>
                <div class="result-message">${result.message}</div>
                ${result.reasons && result.reasons.length > 0 ? `
                    <div style="margin-top: 10px; font-size: 11px; opacity: 0.8;">
                        <strong>Detection reasons:</strong><br>
                        ${result.reasons.slice(0, 2).map(reason => `• ${reason}`).join('<br>')}
                        ${result.reasons.length > 2 ? '<br>• And more...' : ''}
                    </div>
                ` : ''}
            </div>
        `;
        
        if (result.is_phishing && result.confidence > 0.8) {
            const blockButton = document.createElement('button');
            blockButton.className = 'scan-button';
            blockButton.style.background = 'linear-gradient(45deg, #F44336, #E91E63)';
            blockButton.style.marginTop = '10px';
            blockButton.innerHTML = '🚫 Block This Site';
            blockButton.onclick = () => this.blockSite(document.getElementById('url-input').value);
            resultContainer.querySelector('.scan-result').appendChild(blockButton);
        }
    }
    
    showError(message) {
        const errorContainer = document.getElementById('error-message');
        errorContainer.innerHTML = `<div class="error-message">${message}</div>`;
        document.getElementById('scan-result').innerHTML = '';
    }
    
    showLoading() {
        document.getElementById('loading-overlay').style.display = 'flex';
        this.isScanning = true;
        
        const scanButton = document.getElementById('scan-button');
        scanButton.disabled = true;
        scanButton.innerHTML = `<div class="spinner"></div>Scanning...`;
    }
    
    hideLoading() {
        document.getElementById('loading-overlay').style.display = 'none';
        this.isScanning = false;
        
        const scanButton = document.getElementById('scan-button');
        scanButton.disabled = false;
        scanButton.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 16px; height: 16px;">
                <path d="M9 12l2 2 4-4"/>
                <path d="M21 12c-1 0-3-1-3-3s2-3 3-3 3 1 3 3-2 3-3 3"/>
                <path d="M3 12c1 0 3-1 3-3s-2-3-3-3-3 1-3 3 2 3 3 3"/>
            </svg>
            Scan URL
        `;
    }
    
    // FUNCTIONAL BUTTON IMPLEMENTATIONS
    
    showSettings() {
        const resultContainer = document.getElementById('scan-result');
        resultContainer.innerHTML = `
            <div class="scan-result safe">
                <div class="result-header">
                    <div class="result-icon">⚙️</div>
                    <div class="result-title">Extension Settings</div>
                </div>
                <div style="text-align: left; margin: 15px 0;">
                    <div style="margin: 10px 0;">
                        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                            <input type="checkbox" id="auto-scan" checked style="margin: 0;">
                            <span style="font-size: 12px;">Auto-scan websites on navigation</span>
                        </label>
                    </div>
                    <div style="margin: 10px 0;">
                        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                            <input type="checkbox" id="show-notifications" checked style="margin: 0;">
                            <span style="font-size: 12px;">Show threat notifications</span>
                        </label>
                    </div>
                    <div style="margin: 10px 0;">
                        <label style="display: block; font-size: 12px; margin-bottom: 5px;">Detection Sensitivity:</label>
                        <select id="sensitivity" style="width: 100%; padding: 5px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.3); background: rgba(255,255,255,0.1); color: white;">
                            <option value="0.6">High (60% threshold)</option>
                            <option value="0.7" selected>Medium (70% threshold)</option>
                            <option value="0.8">Low (80% threshold)</option>
                        </select>
                    </div>
                </div>
                <div style="display: flex; gap: 10px; margin-top: 15px;">
                    <button onclick="popup.saveSettings()" style="flex: 1; padding: 8px; background: linear-gradient(45deg, #4CAF50, #8BC34A); color: white; border: none; border-radius: 6px; cursor: pointer;">
                        Save Settings
                    </button>
                    <button onclick="popup.clearAllData()" style="flex: 1; padding: 8px; background: linear-gradient(45deg, #F44336, #E91E63); color: white; border: none; border-radius: 6px; cursor: pointer;">
                        Clear All Data
                    </button>
                </div>
            </div>
        `;
        
        // Load current settings
        chrome.storage.local.get(['settings']).then(result => {
            const settings = result.settings || {};
            if (settings.autoScan !== undefined) {
                document.getElementById('auto-scan').checked = settings.autoScan;
            }
            if (settings.showNotifications !== undefined) {
                document.getElementById('show-notifications').checked = settings.showNotifications;
            }
            if (settings.sensitivity !== undefined) {
                document.getElementById('sensitivity').value = settings.sensitivity;
            }
        });
    }
    
    async saveSettings() {
        const settings = {
            autoScan: document.getElementById('auto-scan').checked,
            showNotifications: document.getElementById('show-notifications').checked,
            sensitivity: parseFloat(document.getElementById('sensitivity').value)
        };
        
        await chrome.storage.local.set({ settings });
        this.showError('Settings saved successfully!');
        
        // Clear the error message after 2 seconds
        setTimeout(() => {
            document.getElementById('error-message').innerHTML = '';
        }, 2000);
    }
    
    async clearAllData() {
        if (confirm('Are you sure you want to clear all extension data? This will reset statistics and scan history.')) {
            await chrome.storage.local.clear();
            this.stats = {
                urlsScanned: 0,
                threatsBlocked: 0,
                lastUpdate: new Date()
            };
            this.updateStatsDisplay();
            this.showError('All data cleared successfully!');
            
            setTimeout(() => {
                document.getElementById('error-message').innerHTML = '';
            }, 2000);
        }
    }
    
    async showHistory() {
        try {
            const result = await chrome.storage.local.get(['scanHistory']);
            const history = result.scanHistory || [];
            
            const resultContainer = document.getElementById('scan-result');
            
            if (history.length === 0) {
                resultContainer.innerHTML = `
                    <div class="scan-result safe">
                        <div class="result-header">
                            <div class="result-icon">📊</div>
                            <div class="result-title">Scan History</div>
                        </div>
                        <div class="result-message">No scan history available yet. Start scanning URLs to see your history here.</div>
                    </div>
                `;
                return;
            }
            
            const historyHtml = history.slice(-10).reverse().map(entry => {
                const date = new Date(entry.timestamp).toLocaleDateString();
                const time = new Date(entry.timestamp).toLocaleTimeString();
                const statusColor = entry.is_phishing ? '#ff6b6b' : '#4ecdc4';
                const statusIcon = entry.is_phishing ? '⚠️' : '✅';
                
                return `
                    <div style="padding: 10px; background: rgba(255,255,255,0.05); margin: 8px 0; border-radius: 8px; border-left: 3px solid ${statusColor};">
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 5px;">
                            <span>${statusIcon}</span>
                            <span style="font-weight: 600; color: ${statusColor}; font-size: 12px;">
                                ${entry.is_phishing ? 'PHISHING' : 'SAFE'}
                            </span>
                            <span style="margin-left: auto; font-size: 10px; opacity: 0.6;">
                                ${Math.round(entry.confidence * 100)}%
                            </span>
                        </div>
                        <div style="font-size: 11px; opacity: 0.8; word-break: break-all; margin-bottom: 5px;">
                            ${this.truncateUrl(entry.url)}
                        </div>
                        <div style="font-size: 10px; opacity: 0.6;">
                            ${date} at ${time}
                        </div>
                    </div>
                `;
            }).join('');
            
            resultContainer.innerHTML = `
                <div class="scan-result safe">
                    <div class="result-header">
                        <div class="result-icon">📊</div>
                        <div class="result-title">Recent Scan History</div>
                        <div class="result-confidence">${history.length} total scans</div>
                    </div>
                    <div style="max-height: 250px; overflow-y: auto; margin: 10px -5px;">
                        ${historyHtml}
                    </div>
                    <button onclick="popup.exportHistory()" style="width: 100%; padding: 8px; background: linear-gradient(45deg, #667eea, #764ba2); color: white; border: none; border-radius: 6px; cursor: pointer; margin-top: 10px;">
                        Export History
                    </button>
                </div>
            `;
            
        } catch (error) {
            this.showError('Unable to load scan history.');
        }
    }
    
    async exportHistory() {
        try {
            const result = await chrome.storage.local.get(['scanHistory', 'stats']);
            const data = {
                exportDate: new Date().toISOString(),
                statistics: result.stats || this.stats,
                scanHistory: result.scanHistory || []
            };
            
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            
            // Create download link
            const a = document.createElement('a');
            a.href = url;
            a.download = `phishing-detector-history-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            this.showError('History exported successfully!');
            setTimeout(() => {
                document.getElementById('error-message').innerHTML = '';
            }, 2000);
            
        } catch (error) {
            this.showError('Failed to export history.');
        }
    }
    
    showHelp() {
        const resultContainer = document.getElementById('scan-result');
        resultContainer.innerHTML = `
            <div class="scan-result safe">
                <div class="result-header">
                    <div class="result-icon">❓</div>
                    <div class="result-title">Help & Information</div>
                </div>
                <div style="text-align: left; font-size: 12px; line-height: 1.4; margin: 15px 0;">
                    <div style="margin: 12px 0;">
                        <strong style="color: #4ecdc4;">How it works:</strong><br>
                        • Automatically scans websites as you browse<br>
                        • Uses AI to detect phishing attempts<br>
                        • Blocks dangerous sites with full-screen warnings
                    </div>
                    
                    <div style="margin: 12px 0;">
                        <strong style="color: #4ecdc4;">Status indicators:</strong><br>
                        • 🟢 Green badge: Site is safe<br>
                        • 🔴 Red badge: Threat detected<br>
                        • ⚠️ Warning: Suspicious activity
                    </div>
                    
                    <div style="margin: 12px 0;">
                        <strong style="color: #4ecdc4;">Tips for staying safe:</strong><br>
                        • Always check URLs before clicking<br>
                        • Look for HTTPS encryption<br>
                        • Never enter passwords on suspicious sites<br>
                        • Be cautious of urgent email requests
                    </div>
                </div>
                
                <div style="display: flex; gap: 8px; margin-top: 15px;">
                    <button onclick="popup.showAbout()" style="flex: 1; padding: 8px; background: linear-gradient(45deg, #667eea, #764ba2); color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 11px;">
                        About Extension
                    </button>
                    <button onclick="popup.reportBug()" style="flex: 1; padding: 8px; background: linear-gradient(45deg, #FF9800, #FFC107); color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 11px;">
                        Report Bug
                    </button>
                </div>
            </div>
        `;
    }
    
    showAbout() {
        const resultContainer = document.getElementById('scan-result');
        resultContainer.innerHTML = `
            <div class="scan-result safe">
                <div class="result-header">
                    <div class="result-icon">🛡️</div>
                    <div class="result-title">About Phishing Detector</div>
                </div>
                <div style="text-align: center; font-size: 12px; line-height: 1.5; margin: 15px 0;">
                    <div style="margin: 15px 0;">
                        <strong>Version:</strong> 2.0.0<br>
                        <strong>AI-Powered Protection</strong>
                    </div>
                    
                    <div style="margin: 15px 0; text-align: left;">
                        <strong>Features:</strong><br>
                        • Real-time phishing detection<br>
                        • Advanced AI analysis<br>
                        • Beautiful modern interface<br>
                        • Automatic site blocking<br>
                        • Statistics tracking<br>
                        • Export functionality
                    </div>
                    
                    <div style="margin: 15px 0; padding: 10px; background: rgba(255,255,255,0.1); border-radius: 6px;">
                        <strong>Developer:</strong><br>
                        Built for hackathon project<br>
                        Using Flask backend + Chrome extension
                    </div>
                    
                    <div style="margin: 15px 0; font-size: 11px; opacity: 0.8;">
                        This extension helps protect you from phishing attacks by analyzing URLs and blocking dangerous sites before you can interact with them.
                    </div>
                </div>
            </div>
        `;
    }
    
    reportBug() {
        // Create a pre-filled email or GitHub issue
        const subject = encodeURIComponent('Phishing Detector Bug Report');
        const body = encodeURIComponent(`
Please describe the bug you encountered:

Extension Version: 2.0.0
Browser: Chrome
Date: ${new Date().toLocaleDateString()}

Steps to reproduce:
1. 
2. 
3. 

Expected behavior:

Actual behavior:

Additional information:
        `);
        
        // You can change this to your actual email or GitHub issues URL
        const mailtoLink = `mailto:your.email@example.com?subject=${subject}&body=${body}`;
        
        try {
            chrome.tabs.create({ url: mailtoLink });
        } catch (error) {
            this.showError('Please email bug reports to: your.email@example.com');
        }
    }
    
    async saveScanToHistory(url, result) {
        try {
            const historyResult = await chrome.storage.local.get(['scanHistory']);
            const scanHistory = historyResult.scanHistory || [];
            
            const historyEntry = {
                url,
                is_phishing: result.is_phishing,
                confidence: result.confidence,
                risk_level: result.risk_level,
                reasons: result.reasons || [],
                timestamp: new Date().toISOString()
            };
            
            scanHistory.push(historyEntry);
            
            // Keep only last 100 entries
            if (scanHistory.length > 100) {
                scanHistory.splice(0, scanHistory.length - 100);
            }
            
            await chrome.storage.local.set({ scanHistory });
            
        } catch (error) {
            console.error('Error saving scan to history:', error);
        }
    }
    
    updateStatsDisplay() {
        document.getElementById('urls-scanned').textContent = this.stats.urlsScanned.toString();
        document.getElementById('threats-blocked').textContent = this.stats.threatsBlocked.toString();
        document.getElementById('last-update').textContent = this.formatLastUpdate(this.stats.lastUpdate);
    }
    
    formatLastUpdate(date) {
        const now = new Date();
        const diff = now - new Date(date);
        const minutes = Math.floor(diff / 60000);
        
        if (minutes < 1) return 'Now';
        if (minutes < 60) return `${minutes}m ago`;
        if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
        return `${Math.floor(minutes / 1440)}d ago`;
    }
    
    truncateUrl(url) {
        if (url.length <= 45) return url;
        return url.substring(0, 42) + '...';
    }
    
    async blockSite(url) {
        try {
            const result = await chrome.storage.local.get(['blockedSites']);
            const blockedSites = result.blockedSites || [];
            
            if (!blockedSites.includes(url)) {
                blockedSites.push(url);
                await chrome.storage.local.set({ blockedSites });
            }
            
            this.showError(`Site blocked successfully! It will be automatically blocked on future visits.`);
            
            setTimeout(() => {
                document.getElementById('error-message').innerHTML = '';
            }, 3000);
            
        } catch (error) {
            console.error('Error blocking site:', error);
            this.showError('Unable to block site. Please try again.');
        }
    }
}

// Make popup instance globally available for button onclick handlers
let popup;

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    popup = new ExtensionPopup();
});