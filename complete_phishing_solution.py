# complete_phishing_solution.py
# This script combines everything into a single workflow

import pandas as pd
import numpy as np
import requests
import time
import random
from urllib.parse import urlparse
import socket
import ssl
import re
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# ML imports
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import RobustScaler
from sklearn.feature_selection import SelectKBest, f_classif
from imblearn.over_sampling import SMOTE
from imblearn.ensemble import BalancedRandomForestClassifier
import joblib

print("🛡️  Starting Complete Phishing Detection Solution")
print("=" * 60)

class CompleteSolution:
    def __init__(self):
        self.phishing_urls = []
        self.legitimate_urls = []
        self.model = None
        self.scaler = None
        self.feature_selector = None
        
    def step1_collect_data(self):
        """Step 1: Collect comprehensive dataset"""
        print("\n📊 Step 1: Collecting Data...")
        
        # Collect phishing URLs from multiple sources
        self.collect_phishing_urls()
        
        # Generate legitimate URLs
        self.generate_legitimate_urls()
        
        print(f"✅ Collected {len(self.phishing_urls)} phishing URLs")
        print(f"✅ Collected {len(self.legitimate_urls)} legitimate URLs")
        
    def collect_phishing_urls(self):
        """Collect phishing URLs with improved methods"""
        
        # Method 1: Try PhishTank (if available)
        try:
            print("Fetching from PhishTank...")
            response = requests.get("http://data.phishtank.com/data/online-valid.json", timeout=30)
            if response.status_code == 200:
                data = response.json()[:2000]  # Limit to 2000
                phishing_urls = [entry['url'] for entry in data if 'url' in entry]
                self.phishing_urls.extend(phishing_urls)
                print(f"  ✓ Got {len(phishing_urls)} URLs from PhishTank")
        except:
            print("  ⚠️ PhishTank not available")
        
        # Method 2: Try OpenPhish (if available)
        try:
            print("Fetching from OpenPhish...")
            response = requests.get("https://openphish.com/feed.txt", timeout=30)
            if response.status_code == 200:
                urls = response.text.strip().split('\n')[:2000]
                self.phishing_urls.extend(urls)
                print(f"  ✓ Got {len(urls)} URLs from OpenPhish")
        except:
            print("  ⚠️ OpenPhish not available")
        
        # Method 3: Generate synthetic phishing URLs (for training purposes)
        synthetic_phishing = self.generate_synthetic_phishing_urls()
        self.phishing_urls.extend(synthetic_phishing)
        print(f"  ✓ Generated {len(synthetic_phishing)} synthetic phishing URLs")
        
        # Remove duplicates
        self.phishing_urls = list(set(self.phishing_urls))
        
    def generate_synthetic_phishing_urls(self):
        """Generate synthetic phishing URLs for training"""
        legitimate_brands = [
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'instagram', 'twitter', 'linkedin', 'netflix', 'spotify', 'adobe',
            'dropbox', 'github', 'yahoo', 'outlook', 'gmail'
        ]
        
        suspicious_domains = [
            '.tk', '.ml', '.ga', '.cf', '.ru', '.cn', '-security.com',
            '-verify.net', '-update.org', '-login.info', '-account.biz'
        ]
        
        phishing_keywords = [
            'secure', 'verify', 'update', 'confirm', 'suspend', 'limited',
            'urgent', 'immediate', 'click', 'now', 'here', 'validation'
        ]
        
        synthetic_urls = []
        
        for brand in legitimate_brands:
            for _ in range(20):  # Generate 20 variants per brand
                # Choose suspicious pattern
                pattern_type = random.choice(['subdomain', 'domain', 'path', 'mixed'])
                
                if pattern_type == 'subdomain':
                    # Suspicious subdomain
                    keyword = random.choice(phishing_keywords)
                    domain_suffix = random.choice(suspicious_domains)
                    url = f"http://{brand}-{keyword}.malicious{domain_suffix}/login.php"
                    
                elif pattern_type == 'domain':
                    # Brand name in suspicious domain
                    domain_suffix = random.choice(suspicious_domains)
                    url = f"http://{brand}verification{domain_suffix}"
                    
                elif pattern_type == 'path':
                    # Suspicious path with legitimate-looking domain
                    fake_domain = f"{brand}{random.choice(['-security', '-update', '-verify'])}.com"
                    keyword = random.choice(phishing_keywords)
                    url = f"http://{fake_domain}/{keyword}/{brand}/login/"
                    
                else:  # mixed
                    # Mixed suspicious elements
                    subdomain = random.choice(phishing_keywords)
                    domain = f"{brand}{random.choice(['-', ''])}{random.choice(['secure', 'update', 'verify'])}"
                    tld = random.choice(suspicious_domains)
                    path = random.choice(['login.php', 'verify.html', 'update/', 'secure/'])
                    url = f"http://{subdomain}.{domain}{tld}/{path}"
                
                synthetic_urls.append(url)
        
        # Add some IP-based URLs
        for _ in range(100):
            ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            port = random.choice(['', ':8080', ':8000', ':3000'])
            path = random.choice(['/login.php', '/secure/', '/update.html', '/verify/'])
            synthetic_urls.append(f"http://{ip}{port}{path}")
        
        return synthetic_urls
    
    def generate_legitimate_urls(self):
        """Generate comprehensive legitimate URLs"""
        
        # Top legitimate websites
        legitimate_sites = [
            # Tech companies
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'meta.com',
            'netflix.com', 'spotify.com', 'adobe.com', 'salesforce.com', 'oracle.com',
            
            # Social media
            'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 
            'youtube.com', 'tiktok.com', 'snapchat.com', 'pinterest.com',
            
            # E-commerce
            'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com', 'costco.com',
            'homedepot.com', 'lowes.com', 'macys.com', 'nordstrom.com',
            
            # Financial
            'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
            'americanexpress.com', 'discover.com', 'citibank.com',
            
            # News & Media
            'cnn.com', 'bbc.com', 'nytimes.com', 'washingtonpost.com',
            'reuters.com', 'ap.org', 'npr.org', 'wsj.com',
            
            # Education
            'wikipedia.org', 'khanacademy.org', 'coursera.org', 'edx.org',
            'mit.edu', 'stanford.edu', 'harvard.edu', 'berkeley.edu',
            
            # Government
            'irs.gov', 'usps.com', 'nasa.gov', 'cdc.gov', 'fda.gov',
            'sec.gov', 'treasury.gov', 'whitehouse.gov',
            
            # Travel & Entertainment
            'booking.com', 'expedia.com', 'airbnb.com', 'tripadvisor.com',
            'yelp.com', 'imdb.com', 'espn.com', 'nfl.com'
        ]
        
        legitimate_urls = []
        
        # Generate multiple URL patterns for each site
        for site in legitimate_sites:
            base_patterns = [
                f"https://www.{site}",
                f"https://{site}",
                f"https://www.{site}/",
                f"https://www.{site}/index.html",
                f"https://www.{site}/home",
                f"https://www.{site}/about",
                f"https://www.{site}/about-us",
                f"https://www.{site}/contact",
                f"https://www.{site}/contact-us",
                f"https://www.{site}/help",
                f"https://www.{site}/support",
                f"https://www.{site}/faq",
                f"https://www.{site}/privacy",
                f"https://www.{site}/terms",
                f"https://www.{site}/news",
                f"https://www.{site}/blog"
            ]
            legitimate_urls.extend(base_patterns)
            
            # Add some with parameters (legitimate patterns)
            param_patterns = [
                f"https://www.{site}/search?q=example",
                f"https://www.{site}/products?category=electronics",
                f"https://www.{site}/user/profile",
                f"https://www.{site}/dashboard",
                f"https://www.{site}/account/settings"
            ]
            legitimate_urls.extend(param_patterns)
        
        self.legitimate_urls = legitimate_urls
    
    def step2_extract_features(self):
        """Step 2: Extract comprehensive features"""
        print("\n🔍 Step 2: Extracting Features...")
        
        all_data = []
        total_urls = len(self.phishing_urls) + len(self.legitimate_urls)
        processed = 0
        
        print(f"Processing {len(self.phishing_urls)} phishing URLs...")
        for url in self.phishing_urls[:3000]:  # Limit for faster processing
            features = self.extract_url_features(url)
            features['label'] = 1  # Phishing
            features['url'] = url
            all_data.append(features)
            
            processed += 1
            if processed % 500 == 0:
                print(f"  Processed {processed} URLs...")
        
        print(f"Processing {len(self.legitimate_urls)} legitimate URLs...")
        for url in self.legitimate_urls[:3000]:  # Limit for faster processing
            features = self.extract_url_features(url)
            features['label'] = 0  # Legitimate
            features['url'] = url
            all_data.append(features)
            
            processed += 1
            if processed % 500 == 0:
                print(f"  Processed {processed} URLs...")
        
        # Create DataFrame
        self.df = pd.DataFrame(all_data)
        print(f"✅ Created dataset with {len(self.df)} samples and {len(self.df.columns)-2} features")
        
        # Balance the dataset
        phishing_count = sum(self.df['label'] == 1)
        legitimate_count = sum(self.df['label'] == 0)
        print(f"  Phishing: {phishing_count}, Legitimate: {legitimate_count}")
        
        # Balance classes by sampling
        min_count = min(phishing_count, legitimate_count, 2500)  # Max 2500 per class
        
        phishing_data = self.df[self.df['label'] == 1].sample(n=min_count, random_state=42)
        legitimate_data = self.df[self.df['label'] == 0].sample(n=min_count, random_state=42)
        
        self.df = pd.concat([phishing_data, legitimate_data]).sample(frac=1, random_state=42).reset_index(drop=True)
        print(f"✅ Balanced dataset: {len(self.df)} total samples")
        
    def extract_url_features(self, url):
        """Extract comprehensive features from URL"""
        try:
            parsed = urlparse(url)
            
            features = {
                # Length features
                'url_length': len(url),
                'domain_length': len(parsed.netloc),
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
                'has_ip_address': int(self.is_ip_address(parsed.netloc)),
                'is_https': int(parsed.scheme == 'https'),
                'has_suspicious_port': int(self.has_suspicious_port(parsed.netloc)),
                'is_url_shortener': int(self.is_url_shortener(parsed.netloc)),
                
                # Domain analysis
                'num_subdomains': len(parsed.netloc.split('.')) - 2 if len(parsed.netloc.split('.')) > 2 else 0,
                'subdomain_length': len(parsed.netloc.split('.')[0]) if len(parsed.netloc.split('.')) > 2 else 0,
                
                # TLD analysis
                'tld_length': len(parsed.netloc.split('.')[-1]) if '.' in parsed.netloc else 0,
                'is_common_tld': int(parsed.netloc.endswith(('.com', '.org', '.net', '.edu', '.gov'))),
                'is_suspicious_tld': int(parsed.netloc.endswith(('.tk', '.ml', '.ga', '.cf', '.ru'))),
                
                # Content analysis
                'phishing_keywords_count': self.count_phishing_keywords(url),
                'has_phishing_keywords': int(self.count_phishing_keywords(url) > 0),
                'brand_impersonation': int(self.check_brand_impersonation(url)),
                
                # Entropy and randomness
                'domain_entropy': self.calculate_entropy(parsed.netloc),
                'path_entropy': self.calculate_entropy(parsed.path) if parsed.path else 0,
                'url_entropy': self.calculate_entropy(url),
                
                # Special character ratios
                'special_chars_ratio': self.calculate_special_chars_ratio(url),
                'domain_special_ratio': self.calculate_special_chars_ratio(parsed.netloc),
                
                # Suspicious patterns
                'has_multiple_subdomains': int(len(parsed.netloc.split('.')) > 4),
                'has_suspicious_keywords': int(self.has_suspicious_keywords(url)),
                'has_homograph': int(self.check_homograph_attack(parsed.netloc)),
                
                # Length ratios
                'domain_to_url_ratio': len(parsed.netloc) / len(url) if len(url) > 0 else 0,
                'path_to_url_ratio': len(parsed.path) / len(url) if len(url) > 0 else 0,
                'query_to_url_ratio': len(parsed.query) / len(url) if len(url) > 0 and parsed.query else 0,
                
                # Additional suspicious indicators
                'has_typosquatting': int(self.check_typosquatting(parsed.netloc)),
                'suspicious_file_extension': int(self.has_suspicious_file_extension(parsed.path)),
                'redirect_indicators': int(self.has_redirect_indicators(url))
            }
            
            return features
            
        except Exception as e:
            # Return default features if extraction fails
            return {key: 0 for key in [
                'url_length', 'domain_length', 'path_length', 'query_length',
                'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
                'num_digits', 'num_params', 'has_ip_address', 'is_https',
                'has_suspicious_port', 'is_url_shortener', 'num_subdomains',
                'subdomain_length', 'tld_length', 'is_common_tld', 'is_suspicious_tld',
                'phishing_keywords_count', 'has_phishing_keywords', 'brand_impersonation',
                'domain_entropy', 'path_entropy', 'url_entropy', 'special_chars_ratio',
                'domain_special_ratio', 'has_multiple_subdomains', 'has_suspicious_keywords',
                'has_homograph', 'domain_to_url_ratio', 'path_to_url_ratio',
                'query_to_url_ratio', 'has_typosquatting', 'suspicious_file_extension',
                'redirect_indicators'
            ]}
    
    # Helper methods for feature extraction
    def is_ip_address(self, hostname):
        try:
            socket.inet_aton(hostname.split(':')[0])
            return True
        except:
            return False
    
    def has_suspicious_port(self, netloc):
        suspicious_ports = ['8080', '8000', '3000', '8888', '1234', '8443']
        return any(port in netloc for port in suspicious_ports)
    
    def is_url_shortener(self, domain):
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link', 'tinycc.com']
        return any(shortener in domain.lower() for shortener in shorteners)
    
    def count_phishing_keywords(self, url):
        keywords = [
            'secure', 'account', 'update', 'confirm', 'login', 'signin', 'bank',
            'verify', 'suspended', 'limited', 'click', 'here', 'now', 'urgent',
            'immediate', 'action', 'required', 'validation', 'authentication'
        ]
        url_lower = url.lower()
        return sum(1 for keyword in keywords if keyword in url_lower)
    
    def check_brand_impersonation(self, url):
        brands = [
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'instagram', 'twitter', 'netflix', 'spotify', 'adobe', 'dropbox'
        ]
        url_lower = url.lower()
        
        # Check if brand appears in suspicious context
        for brand in brands:
            if brand in url_lower:
                # Check if it's in a suspicious domain pattern
                if any(suspicious in url_lower for suspicious in ['-', 'verify', 'update', 'secure']):
                    # But not the actual legitimate domain
                    if not url_lower.startswith(f'https://{brand}.com') and not url_lower.startswith(f'https://www.{brand}.com'):
                        return True
        return False
    
    def calculate_entropy(self, text):
        if not text:
            return 0
        
        prob = [text.count(c) / len(text) for c in set(text)]
        entropy = -sum(p * np.log2(p) for p in prob if p > 0)
        return entropy
    
    def calculate_special_chars_ratio(self, text):
        if not text:
            return 0
        special_chars = sum(1 for c in text if not c.isalnum() and c not in '.:/-?=&')
        return special_chars / len(text)
    
    def has_suspicious_keywords(self, url):
        suspicious = [
            'click', 'here', 'now', 'urgent', 'immediate', 'winner', 'congratulations',
            'suspended', 'expires', 'limited', 'offer', 'deal'
        ]
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in suspicious)
    
    def check_homograph_attack(self, domain):
        # Simple check for mixed scripts (basic homograph detection)
        try:
            # Check if domain contains characters from different scripts
            has_latin = any(ord(c) < 128 for c in domain)
            has_cyrillic = any(1024 <= ord(c) <= 1279 for c in domain)
            return has_latin and has_cyrillic
        except:
            return False
    
    def check_typosquatting(self, domain):
        # Check for common typosquatting patterns
        legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'twitter.com', 'instagram.com'
        ]
        
        domain_lower = domain.lower()
        for legit_domain in legitimate_domains:
            # Check for character substitution
            if self.is_similar_domain(domain_lower, legit_domain):
                return True
        return False
    
    def is_similar_domain(self, domain1, domain2):
        # Simple similarity check (Levenshtein distance approximation)
        if abs(len(domain1) - len(domain2)) > 3:
            return False
        
        differences = sum(c1 != c2 for c1, c2 in zip(domain1, domain2))
        return 1 <= differences <= 2
    
    def has_suspicious_file_extension(self, path):
        suspicious_extensions = ['.exe', '.php', '.asp', '.jsp', '.cgi']
        return any(path.lower().endswith(ext) for ext in suspicious_extensions)
    
    def has_redirect_indicators(self, url):
        redirect_keywords = ['redirect', 'goto', 'link', 'redir', 'forward']
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in redirect_keywords)
    
    def step3_train_model(self):
        """Step 3: Train optimized ML model"""
        print("\n🤖 Step 3: Training ML Model...")
        
        # Prepare features and labels
        X = self.df.drop(['label', 'url'], axis=1)
        y = self.df['label']
        
        print(f"Training with {X.shape[0]} samples and {X.shape[1]} features")
        
        # Handle missing values
        X = X.fillna(0)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        self.scaler = RobustScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Feature selection
        self.feature_selector = SelectKBest(score_func=f_classif, k=min(25, X_train_scaled.shape[1]))
        X_train_selected = self.feature_selector.fit_transform(X_train_scaled, y_train)
        X_test_selected = self.feature_selector.transform(X_test_scaled)
        
        print(f"Selected {X_train_selected.shape[1]} most important features")
        
        # Handle class imbalance with SMOTE
        smote = SMOTE(random_state=42)
        X_train_balanced, y_train_balanced = smote.fit_resample(X_train_selected, y_train)
        
        # Train multiple models
        models = {
            'BalancedRandomForest': BalancedRandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            ),
            'GradientBoosting': GradientBoostingClassifier(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=7,
                random_state=42
            ),
            'LogisticRegression': LogisticRegression(
                C=1.0,
                penalty='l2',
                random_state=42,
                max_iter=1000
            )
        }
        
        best_score = 0
        best_model_name = ""
        
        for name, model in models.items():
            print(f"\nTraining {name}...")
            
            # Train model
            model.fit(X_train_balanced, y_train_balanced)
            
            # Cross-validation
            cv_scores = cross_val_score(model, X_train_balanced, y_train_balanced, cv=5, scoring='roc_auc')
            mean_score = cv_scores.mean()
            
            print(f"  CV AUC Score: {mean_score:.4f} (±{cv_scores.std() * 2:.4f})")
            
            # Test set performance
            y_pred_proba = model.predict_proba(X_test_selected)[:, 1]
            test_auc = roc_auc_score(y_test, y_pred_proba)
            print(f"  Test AUC Score: {test_auc:.4f}")
            
            if test_auc > best_score:
                best_score = test_auc
                best_model_name = name
                self.model = model
        
        print(f"\n✅ Best model: {best_model_name} with AUC: {best_score:.4f}")
        
        # Final evaluation
        y_pred = self.model.predict(X_test_selected)
        y_pred_proba = self.model.predict_proba(X_test_selected)[:, 1]
        
        print("\nFinal Model Performance:")
        print(f"AUC Score: {roc_auc_score(y_test, y_pred_proba):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        # Feature importance
        if hasattr(self.model, 'feature_importances_'):
            feature_names = X.columns[self.feature_selector.get_support()].tolist()
            importances = self.model.feature_importances_
            feature_importance = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
            
            print("\nTop 10 Most Important Features:")
            for i, (feature, importance) in enumerate(feature_importance[:10], 1):
                print(f"{i:2d}. {feature}: {importance:.4f}")
    
    def step4_save_model(self):
        """Step 4: Save the trained model"""
        print("\n💾 Step 4: Saving Model...")
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_selector': self.feature_selector,
            'feature_names': list(self.df.drop(['label', 'url'], axis=1).columns)
        }
        
        joblib.dump(model_data, 'phishing_detector_model.pkl')
        print("✅ Model saved as 'phishing_detector_model.pkl'")
    
    def step5_test_predictions(self):
        """Step 5: Test with sample URLs"""
        print("\n🧪 Step 5: Testing Predictions...")
        
        test_urls = [
            # Legitimate URLs
            "https://www.google.com",
            "https://www.amazon.com/products",
            "https://accounts.google.com/signin",
            "https://www.paypal.com/signin",
            "https://www.microsoft.com/office",
            
            # Suspicious URLs (synthetic for testing)
            "http://paypal-verify.malicious.tk/login.php",
            "http://192.168.1.1:8080/secure/update.php",
            "http://amazon-security-check.suspicious-domain.ru",
            "http://google-account-suspended.fake-site.ml/verify",
            "http://microsoft-urgent-update.phishing.cf/immediate"
        ]
        
        for url in test_urls:
            try:
                features = self.extract_url_features(url)
                prediction = self.predict_url(features)
                
                print(f"\nURL: {url}")
                print(f"Prediction: {prediction['prediction']}")
                print(f"Confidence: {prediction['confidence']:.2f}")
                print(f"Phishing Probability: {prediction['phishing_probability']:.2f}")
                
            except Exception as e:
                print(f"Error predicting {url}: {e}")
    
    def predict_url(self, features):
        """Predict if a URL is phishing"""
        try:
            # Convert to DataFrame
            feature_df = pd.DataFrame([features])
            
            # Handle missing columns
            all_features = list(self.df.drop(['label', 'url'], axis=1).columns)
            for col in all_features:
                if col not in feature_df.columns:
                    feature_df[col] = 0
            
            # Reorder columns
            feature_df = feature_df[all_features]
            
            # Scale and select features
            features_scaled = self.scaler.transform(feature_df)
            features_selected = self.feature_selector.transform(features_scaled)
            
            # Predict
            prediction = self.model.predict(features_selected)[0]
            probability = self.model.predict_proba(features_selected)[0]
            
            return {
                'prediction': 'Phishing' if prediction == 1 else 'Legitimate',
                'confidence': float(max(probability)),
                'phishing_probability': float(probability[1]),
                'legitimate_probability': float(probability[0])
            }
            
        except Exception as e:
            return {
                'prediction': 'Unknown',
                'confidence': 0.5,
                'phishing_probability': 0.5,
                'legitimate_probability': 0.5,
                'error': str(e)
            }
    
    def run_complete_solution(self):
        """Run the complete solution pipeline"""
        print("🚀 Running Complete Phishing Detection Solution")
        print("This will create a high-accuracy model from scratch")
        print("=" * 60)
        
        try:
            self.step1_collect_data()
            self.step2_extract_features()
            self.step3_train_model()
            self.step4_save_model()
            self.step5_test_predictions()
            
            print("\n" + "=" * 60)
            print("🎉 SUCCESS! Complete solution finished!")
            print("✅ High-quality dataset created")
            print("✅ Advanced features extracted")
            print("✅ Optimized model trained")
            print("✅ Model saved for production use")
            print("✅ Ready for browser extension integration")
            print("\nNext steps:")
            print("1. Start the Flask API (python app.py)")
            print("2. Load the Chrome extension")
            print("3. Test on real websites")
            
        except Exception as e:
            print(f"\n❌ Error in pipeline: {e}")
            print("Check the error and try again")

# Main execution
if __name__ == "__main__":
    solution = CompleteSolution()
    solution.run_complete_solution()