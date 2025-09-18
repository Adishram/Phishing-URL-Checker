// content-script.js - Basic Content Script for Phishing Detection
(function() {
    'use strict';

    // Don't run on Chrome system pages
    if (location.protocol === 'chrome:' || location.protocol === 'about:' || 
        location.protocol === 'moz-extension:' || location.protocol === 'chrome-extension:') {
        return;
    }

    let isBlocked = false;

    // Check if current site is blocked
    async function checkIfBlocked() {
        try {
            const result = await chrome.storage.local.get(['blockedSites']);
            const blockedSites = result.blockedSites || [];
            const currentUrl = window.location.href;
            const currentDomain = window.location.hostname;
            
            const blocked = blockedSites.some(site => {
                try {
                    const blockedUrl = new URL(site);
                    return blockedUrl.hostname === currentDomain || site === currentUrl;
                } catch {
                    return site === currentUrl || site === currentDomain;
                }
            });
            
            if (blocked) {
                blockCurrentPage('This site has been blocked for your protection.');
            }
            
        } catch (error) {
            console.log('Error checking blocked sites:', error);
        }
    }

    // Block current page with overlay
    function blockCurrentPage(message) {
        if (isBlocked) return;
        isBlocked = true;
        
        const overlay = document.createElement('div');
        overlay.id = 'phishing-detector-overlay';
        overlay.innerHTML = `
            <div style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: linear-gradient(135deg, #ff6b6b 0%, #ff8e53 100%);
                z-index: 999999;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                color: white;
            ">
                <div style="
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    border-radius: 20px;
                    padding: 40px;
                    text-align: center;
                    max-width: 500px;
                    margin: 20px;
                    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
                ">
                    <div style="font-size: 64px; margin-bottom: 20px;">🛡️</div>
                    <h1 style="font-size: 28px; margin-bottom: 15px; font-weight: 700;">
                        Site Blocked
                    </h1>
                    <p style="font-size: 16px; margin-bottom: 25px; line-height: 1.5; opacity: 0.9;">
                        ${message}
                    </p>
                    <div style="font-size: 14px; margin-bottom: 30px; opacity: 0.8;">
                        <strong>URL:</strong> ${window.location.href}
                    </div>
                    <div style="display: flex; gap: 15px; justify-content: center; flex-wrap: wrap;">
                        <button id="pd-go-back" style="
                            background: linear-gradient(45deg, #667eea, #764ba2);
                            color: white;
                            border: none;
                            padding: 12px 24px;
                            border-radius: 8px;
                            font-size: 14px;
                            font-weight: 600;
                            cursor: pointer;
                            transition: all 0.3s ease;
                        ">
                            ← Go Back
                        </button>
                        <button id="pd-continue-anyway" style="
                            background: rgba(255, 255, 255, 0.2);
                            color: white;
                            border: 2px solid rgba(255, 255, 255, 0.3);
                            padding: 10px 22px;
                            border-radius: 8px;
                            font-size: 14px;
                            font-weight: 600;
                            cursor: pointer;
                            transition: all 0.3s ease;
                        ">
                            Continue Anyway (Not Recommended)
                        </button>
                    </div>
                    <div style="margin-top: 20px; font-size: 12px; opacity: 0.7;">
                        Protected by Phishing Detector Extension
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(overlay);
        
        // Add event listeners
        document.getElementById('pd-go-back').addEventListener('click', () => {
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.href = 'about:blank';
            }
        });
        
        document.getElementById('pd-continue-anyway').addEventListener('click', () => {
            if (confirm('Are you sure you want to continue to this potentially dangerous site?')) {
                overlay.remove();
                isBlocked = false;
                document.body.style.overflow = 'auto';
            }
        });
        
        document.body.style.overflow = 'hidden';
    }

    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        switch (message.type) {
            case 'blockPage':
                blockCurrentPage(message.message || 'This site has been identified as potentially dangerous.');
                sendResponse({ success: true });
                break;
            case 'checkPageStatus':
                sendResponse({ 
                    success: true, 
                    isBlocked: isBlocked,
                    url: window.location.href 
                });
                break;
        }
    });

    // Initialize
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', checkIfBlocked);
    } else {
        checkIfBlocked();
    }
})();