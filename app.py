from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
import joblib
import logging
from urllib.parse import urlparse
import socket
import ssl
import re
from datetime import datetime
import webbrowser

app = Flask(__name__)
CORS(app ,origins=["*"],allow_headers=["Content-Type"],methods=["GET","POST","OPTIONS"])

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ImprovedPhishingDetectorAPI:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_selector = None
        self.feature_names = None
        
        # Whitelist of known legitimate domains
        self.legitimate_domains = {
            'google.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'youtube.com',
            'netflix.com', 'spotify.com', 'adobe.com', 'dropbox.com', 'stackoverflow.com',
            'reddit.com', 'wikipedia.org', 'paypal.com', 'ebay.com', 'walmart.com',
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'cnn.com', 'bbc.com',
            'nytimes.com', 'gmail.com', 'outlook.com', 'yahoo.com','netlify.app','vercel.app'
        }
        
        self.load_model()

    def load_model(self):
        """Load the trained model"""
        try:
            model_data = joblib.load('phishing_detector_model.pkl')
            self.model = model_data.get('model')
            self.scaler = model_data.get('scaler')
            self.feature_selector = model_data.get('feature_selector')
            self.feature_names = model_data.get('feature_names')
            logger.info("Model loaded successfully")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self.model = None
            self.scaler = None
            self.feature_selector = None
            self.feature_names = []

    def is_whitelisted_domain(self, domain):
        """Check if domain is in whitelist of legitimate sites"""
        domain = domain.lower().strip()
        
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check exact match
        if domain in self.legitimate_domains:
            return True
            
        # Check if it's a subdomain of a legitimate domain
        for legit_domain in self.legitimate_domains:
            if domain.endswith('.' + legit_domain):
                # Make sure it's a reasonable subdomain (not too long)
                subdomain_part = domain[:-len('.' + legit_domain)]
                if len(subdomain_part) < 20 and '.' not in subdomain_part:
                    return True
        
        return False

    def extract_features(self, url):
        """Extract features from URL with improved accuracy"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            features = {
                # Length features
                'url_length': len(url),
                'domain_length': len(domain),
                'path_length': len(parsed.path),
                'query_length': len(parsed.query) if parsed.query else 0,
                
                # Count features
                'num_dots': url.count('.'),
                'num_hyphens': url.count('-'),
                'num_underscores': url.count('_'),
                'num_slashes': url.count('/'),
                'num_digits': sum(c.isdigit() for c in url),
                'num_params': len(parsed.query.split('&')) if parsed.query else 0,
                
                # Boolean features
                'has_ip_address': int(self._is_ip_address(domain)),
                'is_https': int(parsed.scheme == 'https'),
                'has_suspicious_port': int(self._has_suspicious_port(parsed.netloc)),
                'is_url_shortener': int(self._is_url_shortener(domain)),
                
                # Domain analysis
                'num_subdomains': len(domain.split('.')) - 2 if len(domain.split('.')) > 2 else 0,
                'subdomain_length': len(domain.split('.')[0]) if len(domain.split('.')) > 2 else 0,
                
                # TLD analysis
                'tld_length': len(domain.split('.')[-1]) if '.' in domain else 0,
                'is_common_tld': int(domain.endswith(('.com', '.org', '.net', '.edu', '.gov'))),
                'is_suspicious_tld': int(domain.endswith(('.tk', '.ml', '.ga', '.cf'))),
                
                # Content analysis - IMPROVED
                'phishing_keywords_count': self._count_phishing_keywords(url),
                'has_phishing_keywords': int(self._count_phishing_keywords(url) > 0),
                'brand_impersonation': int(self._check_brand_impersonation_improved(url, domain)),
                
                # Entropy and randomness
                'domain_entropy': self._calculate_entropy(domain),
                'path_entropy': self._calculate_entropy(parsed.path) if parsed.path else 0,
                'url_entropy': self._calculate_entropy(url),
                
                # Special character ratios
                'special_chars_ratio': self._calculate_special_chars_ratio(url),
                'domain_special_ratio': self._calculate_special_chars_ratio(domain),
                
                # Suspicious patterns
                'has_multiple_subdomains': int(len(domain.split('.')) > 4),
                'has_suspicious_keywords': int(self._has_suspicious_keywords(url)),
                'has_homograph': int(self._check_homograph_attack(domain)),
                
                # Length ratios
                'domain_to_url_ratio': len(domain) / len(url) if len(url) > 0 else 0,
                'path_to_url_ratio': len(parsed.path) / len(url) if len(url) > 0 else 0,
                'query_to_url_ratio': len(parsed.query) / len(url) if len(url) > 0 and parsed.query else 0,
                
                # Additional suspicious indicators
                'has_typosquatting': int(self._check_typosquatting_improved(domain)),
                'suspicious_file_extension': int(self._has_suspicious_file_extension(parsed.path)),
                'redirect_indicators': int(self._has_redirect_indicators(url))
            }
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None

    def _check_brand_impersonation_improved(self, url, domain):
        """Improved brand impersonation detection"""
        # Skip if domain is whitelisted
        if self.is_whitelisted_domain(domain):
            return False
        
        brands = [
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'instagram', 'twitter', 'netflix', 'spotify', 'adobe', 'dropbox'
        ]
        
        url_lower = url.lower()
        domain_lower = domain.lower()
        
        for brand in brands:
            if brand in url_lower:
                # Check if it's the legitimate domain first
                legitimate_patterns = [
                    f"{brand}.com",
                    f"www.{brand}.com",
                    f"accounts.{brand}.com",
                    f"secure.{brand}.com",
                    f"login.{brand}.com"
                ]
                
                # If it matches legitimate patterns, it's not impersonation
                if any(pattern in domain_lower for pattern in legitimate_patterns):
                    return False
                
                # Now check for suspicious patterns
                suspicious_indicators = [
                    f"{brand}-verify", f"{brand}-update", f"{brand}-secure",
                    f"{brand}-login", f"{brand}-account", f"secure-{brand}",
                    f"verify-{brand}", f"update-{brand}"
                ]
                
                if any(suspicious in url_lower for suspicious in suspicious_indicators):
                    return True
        
        return False

    def _check_typosquatting_improved(self, domain):
        """Improved typosquatting detection"""
        # Skip if domain is whitelisted
        if self.is_whitelisted_domain(domain):
            return False
        
        legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'twitter.com', 'instagram.com',
            'github.com', 'linkedin.com', 'youtube.com'
        ]
        
        domain_lower = domain.lower()
        
        for legit_domain in legitimate_domains:
            # Check for character substitution
            if self._is_similar_domain(domain_lower, legit_domain):
                # Additional check: make sure it's not a legitimate subdomain
                if not domain_lower.endswith('.' + legit_domain):
                    return True
        
        return False

    def _is_similar_domain(self, domain1, domain2):
        """Check if domains are similar (potential typosquatting)"""
        if abs(len(domain1) - len(domain2)) > 3:
            return False
        
        differences = sum(c1 != c2 for c1, c2 in zip(domain1, domain2))
        return 1 <= differences <= 2

    def _is_ip_address(self, hostname):
        """Check if hostname is an IP address"""
        try:
            socket.inet_aton(hostname.split(':')[0])
            return True
        except Exception:
            return False

    def _has_suspicious_port(self, netloc):
        """Check for suspicious ports"""
        suspicious_ports = ['8080', '8000', '3000', '8888', '1234', '8443']
        return any(port in netloc for port in suspicious_ports)

    def _is_url_shortener(self, domain):
        """Check if domain is a known URL shortener"""
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link', 'tinycc.com']
        return any(shortener in domain.lower() for shortener in shorteners)

    def _count_phishing_keywords(self, url):
        """Count phishing keywords in URL"""
        keywords = [
            'secure', 'account', 'update', 'confirm', 'login', 'signin', 'bank',
            'verify', 'suspended', 'limited', 'click', 'here', 'now', 'urgent',
            'immediate', 'action', 'required', 'validation', 'authentication'
        ]
        url_lower = url.lower()
        return sum(1 for keyword in keywords if keyword in url_lower)

    def _calculate_entropy(self, text):
        """Calculate entropy of text"""
        if not text:
            return 0
        prob = [text.count(c) / len(text) for c in set(text)]
        entropy = -sum(p * np.log2(p) for p in prob if p > 0)
        return entropy

    def _calculate_special_chars_ratio(self, text):
        """Calculate ratio of special characters"""
        if not text:
            return 0
        special_chars = sum(1 for c in text if not c.isalnum() and c not in '.:/-?=&')
        return special_chars / len(text)

    def _has_suspicious_keywords(self, url):
        """Check for suspicious keywords"""
        suspicious = [
            'click', 'here', 'now', 'urgent', 'immediate', 'winner', 'congratulations',
            'suspended', 'expires', 'limited', 'offer', 'deal'
        ]
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in suspicious)

    def _check_homograph_attack(self, domain):
        """Check for homograph attacks (mixed scripts)"""
        try:
            has_latin = any(ord(c) < 128 for c in domain)
            has_cyrillic = any(1024 <= ord(c) <= 1279 for c in domain)
            return has_latin and has_cyrillic
        except Exception:
            return False

    def _has_suspicious_file_extension(self, path):
        """Check for suspicious file extensions"""
        suspicious_extensions = ['.exe', '.php', '.asp', '.jsp', '.cgi']
        return any(path.lower().endswith(ext) for ext in suspicious_extensions)

    def _has_redirect_indicators(self, url):
        """Check for redirect indicators"""
        redirect_keywords = ['redirect', 'goto', 'link', 'redir', 'forward']
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in redirect_keywords)

    def predict(self, url):
        """Make prediction for a URL with improved accuracy"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Check whitelist first
            if self.is_whitelisted_domain(domain):
                return {
                    'prediction': 'Legitimate',
                    'confidence': 0.95,
                    'phishing_probability': 0.05,
                    'legitimate_probability': 0.95,
                    'reason': 'Whitelisted domain'
                }
            
            # Extract features
            features = self.extract_features(url)
            if not features:
                return self._fallback_prediction(url)
            
            # Use trained model if available
            if self.model is not None:
                return self._ml_prediction(features)
            else:
                return self._improved_fallback_prediction(url, features, domain)
                
        except Exception as e:
            logger.error(f"Error in prediction: {e}")
            return {
                'prediction': 'Legitimate',
                'confidence': 0.5,
                'phishing_probability': 0.5,
                'legitimate_probability': 0.5,
                'error': str(e)
            }

    def _ml_prediction(self, features):
        """Use ML model for prediction"""
        try:
            feature_df = pd.DataFrame([features])
            
            for col in self.feature_names:
                if col not in feature_df.columns:
                    feature_df[col] = 0
            
            feature_df = feature_df[self.feature_names]
            features_scaled = self.scaler.transform(feature_df)
            features_selected = self.feature_selector.transform(features_scaled)
            
            prediction = self.model.predict(features_selected)[0]
            probability = self.model.predict_proba(features_selected)[0]
            
            return {
                'prediction': 'Phishing' if prediction == 1 else 'Legitimate',
                'confidence': float(max(probability)),
                'phishing_probability': float(probability[1]),
                'legitimate_probability': float(probability[0])
            }
            
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return self._improved_fallback_prediction(None, features, None)

    def _improved_fallback_prediction(self, url, features, domain):
        """Improved fallback prediction using heuristics"""
        if not features:
            return {
                'prediction': 'Legitimate',
                'confidence': 0.5,
                'phishing_probability': 0.5,
                'legitimate_probability': 0.5,
                'fallback': True
            }
        
        score = 0
        reasons = []
        
        # Apply improved heuristic rules
        if features.get('has_ip_address'):
            score += 0.4
            reasons.append("IP address instead of domain")
        
        if features.get('brand_impersonation'):
            score += 0.5
            reasons.append("Brand impersonation detected")
        
        if features.get('phishing_keywords_count', 0) > 3:
            score += 0.3
            reasons.append("Multiple phishing keywords")
        elif features.get('phishing_keywords_count', 0) > 1:
            score += 0.15
        
        if features.get('is_suspicious_tld'):
            score += 0.3
            reasons.append("Suspicious TLD")
        
        if features.get('has_typosquatting'):
            score += 0.4
            reasons.append("Typosquatting detected")
        
        if features.get('num_subdomains', 0) > 4:
            score += 0.2
            reasons.append("Excessive subdomains")
        elif features.get('num_subdomains', 0) > 2:
            score += 0.1
        
        if features.get('url_length', 0) > 150:
            score += 0.2
            reasons.append("Very long URL")
        elif features.get('url_length', 0) > 100:
            score += 0.1
        
        if not features.get('is_https', 1):
            score += 0.15
            reasons.append("No HTTPS encryption")
        
        if features.get('has_suspicious_port'):
            score += 0.25
            reasons.append("Suspicious port")
        
        if features.get('is_url_shortener'):
            score += 0.1  # Reduced - not always malicious
        
        if features.get('domain_entropy', 0) > 4.5:
            score += 0.15
            reasons.append("High domain randomness")
        
        if features.get('special_chars_ratio', 0) > 0.15:
            score += 0.15
            reasons.append("High special character ratio")
        
        if features.get('has_homograph'):
            score += 0.4
            reasons.append("Homograph attack")
        
        if features.get('suspicious_file_extension'):
            score += 0.2
            reasons.append("Suspicious file extension")
        
        if features.get('redirect_indicators'):
            score += 0.1
        
        # Normalize score to probability (cap at 1.0)
        phishing_prob = min(score, 1.0)
        legitimate_prob = 1.0 - phishing_prob
        
        # Determine prediction
        is_phishing = score > 0.5
        confidence = max(phishing_prob, legitimate_prob)
        
        return {
            'prediction': 'Phishing' if is_phishing else 'Legitimate',
            'confidence': confidence,
            'phishing_probability': phishing_prob,
            'legitimate_probability': legitimate_prob,
            'reasons': reasons,
            'score': score,
            'fallback': True
        }

    def _fallback_prediction(self, url):
        """Simple fallback when feature extraction fails"""
        return {
            'prediction': 'Legitimate',
            'confidence': 0.5,
            'phishing_probability': 0.5,
            'legitimate_probability': 0.5,
            'fallback': True,
            'error': 'Feature extraction failed'
        }

# Initialize detector
detector = ImprovedPhishingDetectorAPI()

@app.route('/predict', methods=['OPTIONS'])
def predict_options():
    return ("", 204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
    })

@app.route('/predict', methods=['POST', 'OPTIONS'])
def predict_alias():
    if request.method == 'OPTIONS':
        return ("", 204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type,Authorization"
        })

    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        url = data['url'].strip()
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            if not url.startswith('www.'):
                url = 'https://' + url
            else:
                url = 'https://' + url

        result = detector.predict(url)
        result['url'] = url
        result['timestamp'] = datetime.now().isoformat()

        # Determine risk level based on confidence and prediction
        is_phishing = result.get("prediction", "").lower() == "phishing"
        confidence = float(result.get("confidence", 0.5))
        
        if is_phishing:
            if confidence >= 0.8:
                risk_level = "High"
            elif confidence >= 0.6:
                risk_level = "Medium"
            else:
                risk_level = "Low"
        else:
            risk_level = "Low"

        # Create a clear message
        if is_phishing:
            if confidence >= 0.8:
                message = "This URL is very likely to be a phishing attempt. Avoid visiting this site."
            elif confidence >= 0.6:
                message = "This URL shows signs of being a phishing attempt. Exercise caution."
            else:
                message = "This URL may be suspicious. Please verify before entering personal information."
        else:
            if result.get('reason') == 'Whitelisted domain':
                message = "This is a verified legitimate website."
            else:
                message = "This URL appears to be legitimate, but always exercise caution online."

        return jsonify({
            "is_phishing": is_phishing,
            "confidence": confidence,
            "risk_level": risk_level,
            "message": message,
            "features": detector.extract_features(url) or {},
            "reasons": result.get("reasons", []),
            "raw": result,
            "url": url,
            "timestamp": result['timestamp']
        })

    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Keep other routes the same...
@app.route('/api/check-url', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        if not url.startswith(('http://', 'https://')):
            return jsonify({'error': 'Invalid URL format'}), 400
        
        result = detector.predict(url)
        result['url'] = url
        result['timestamp'] = datetime.now().isoformat()
        logger.info(f"Checked URL: {url}, Result: {result['prediction']}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'model_loaded': detector.model is not None,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'message': 'Improved Phishing URL Detection API',
        'version': '2.0.0',
        'improvements': [
            'Better brand impersonation detection',
            'Domain whitelist for accuracy',
            'Improved typosquatting detection',
            'Enhanced heuristics'
        ],
        'model_status': 'loaded' if detector.model else 'fallback_mode',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/test', methods=['GET'])
def test_endpoint():
    test_urls = [
        "https://www.google.com",
        "https://github.com/yourusername",
        "https://www.amazon.com",
        "http://paypal-verify.suspicious.tk/login.php",
        "http://192.168.1.1:8080/secure.php"
    ]
    
    results = []
    for url in test_urls:
        result = detector.predict(url)
        result['url'] = url
        results.append(result)
    
    return jsonify({
        'test_results': results,
        'model_status': 'loaded' if detector.model else 'improved_fallback_mode'
    })

if __name__ == '__main__':
    print("🚀 Starting Improved Phishing Detection API Server...")
    print("📡 Server will run on http://127.0.0.1:5000")
    print("🔍 Improvements:")
    print("   - Domain whitelist for better accuracy")
    print("   - Improved brand impersonation detection")  
    print("   - Better heuristics scoring")
    print("🤖 Model status:", "Loaded" if detector.model else "Improved Fallback mode")
    
    app.run(debug=True, port=5000, host='127.0.0.1')
