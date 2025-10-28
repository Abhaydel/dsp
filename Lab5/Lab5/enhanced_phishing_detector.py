import pandas as pd
from urllib.parse import urlparse
import re
import requests
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os
from datetime import datetime


class PhishingDetector:
    def __init__(self):
        self.model = None
        self.feature_names = []
        
    def extract_features(self, url):
        """Extract 17 features from URL as mentioned in the research project"""
        features = {}
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path
            query = parsed_url.query
            
            # Address Bar Based Features (9 features)
            
            # 1. URL Length
            features['url_length'] = len(url)
            
            # 2. Uses HTTPS
            features['uses_https'] = 1 if parsed_url.scheme == 'https' else 0
            
            # 3. Contains @ symbol
            features['contains_at'] = 1 if '@' in url else 0
            
            # 4. Contains double slash in path
            features['double_slash_path'] = 1 if '//' in path else 0
            
            # 5. Contains dash in domain
            features['dash_in_domain'] = 1 if '-' in domain else 0
            
            # 6. Number of subdomains
            subdomains = domain.split('.')
            features['subdomain_count'] = max(0, len(subdomains) - 2)
            
            # 7. URL depth (number of '/' in path)
            features['url_depth'] = path.count('/')
            
            # 8. Contains suspicious keywords
            suspicious_keywords = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm']
            features['suspicious_keywords'] = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
            
            # 9. Length of hostname
            features['hostname_length'] = len(domain)
            
            # Domain Based Features (4 features)
            
            # 10. Contains IP address instead of domain
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            features['contains_ip'] = 1 if re.search(ip_pattern, domain) else 0
            
            # 11. Domain age (simplified - checking if it's a well-known domain)
            well_known_domains = ['google', 'microsoft', 'apple', 'amazon', 'facebook', 'twitter', 'linkedin', 'netflix', 'youtube', 'instagram']
            features['well_known_domain'] = 1 if any(wd in domain for wd in well_known_domains) else 0
            
            # 12. Number of dots in domain
            features['dots_in_domain'] = domain.count('.')
            
            # 13. Contains numbers in domain
            features['numbers_in_domain'] = 1 if any(char.isdigit() for char in domain) else 0
            
            # HTML & JavaScript Based Features (4 features) - Simplified
            
            # 14. Uses URL shortening service
            shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd"
            features['uses_shortening'] = 1 if re.search(shortening_services, url.lower()) else 0
            
            # 15. Suspicious TLD
            suspicious_tlds = ['.tk', '.ml', '.cf', '.ga', '.click', '.download', '.link']
            features['suspicious_tld'] = 1 if any(tld in url.lower() for tld in suspicious_tlds) else 0
            
            # 16. Query parameters count
            features['query_params'] = len(query.split('&')) if query else 0
            
            # 17. Special characters count
            special_chars = ['%', '&', '?', '#', '=']
            features['special_chars_count'] = sum(url.count(char) for char in special_chars)
            
        except Exception as e:
            # If URL parsing fails, return default values
            print(f"Error parsing URL {url}: {e}")
            features = {f'feature_{i}': 0 for i in range(17)}
            
        return features
    
    def train_model(self, df):
        """Train the phishing detection model"""
        print("Extracting features from URLs...")
        
        # Extract features for all URLs
        features_list = []
        for url in df['url']:
            features = self.extract_features(url)
            features_list.append(features)
        
        # Convert to DataFrame
        features_df = pd.DataFrame(features_list)
        self.feature_names = features_df.columns.tolist()
        
        # Prepare training data
        X = features_df
        y = df['label'].map({'benign': 0, 'phishing': 1})
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        print("Training Random Forest model...")
        self.model = RandomForestClassifier(
            n_estimators=100, 
            random_state=42, 
            n_jobs=-1,
            max_depth=10
        )
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model Accuracy: {accuracy * 100:.2f}%")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Benign', 'Phishing']))
        
        return accuracy
    
    def predict_url(self, url):
        """Predict if a URL is phishing or benign"""
        if self.model is None:
            raise ValueError("Model not trained yet!")
        
        features = self.extract_features(url)
        features_df = pd.DataFrame([features])
        
        # Ensure all features are present
        for feature_name in self.feature_names:
            if feature_name not in features_df.columns:
                features_df[feature_name] = 0
        
        # Reorder columns to match training data
        features_df = features_df[self.feature_names]
        
        prediction = self.model.predict(features_df)[0]
        probability = self.model.predict_proba(features_df)[0]
        
        return {
            'prediction': 'Phishing' if prediction == 1 else 'Benign',
            'confidence': max(probability) * 100,
            'probability_benign': probability[0] * 100,
            'probability_phishing': probability[1] * 100,
            'features': features
        }
    
    def save_model(self, filepath='phishing_model.pkl'):
        """Save the trained model"""
        model_data = {
            'model': self.model,
            'feature_names': self.feature_names
        }
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath='phishing_model.pkl'):
        """Load a pre-trained model"""
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            self.model = model_data['model']
            self.feature_names = model_data['feature_names']
            print(f"Model loaded from {filepath}")
            return True
        return False


def create_sample_data():
    """Create a more comprehensive sample dataset"""
    benign_urls = [
        'https://www.google.com',
        'https://www.microsoft.com',
        'https://www.apple.com',
        'https://www.amazon.com',
        'https://www.facebook.com',
        'https://www.twitter.com',
        'https://www.linkedin.com',
        'https://www.netflix.com',
        'https://www.spotify.com',
        'https://www.youtube.com',
        'https://www.instagram.com',
        'https://www.github.com',
        'https://www.stackoverflow.com',
        'https://www.wikipedia.org',
        'https://www.reddit.com'
    ]
    
    phishing_urls = [
        'http://paypal-security.com/signin',
        'https://amazon-security.tk/login',
        'http://192.168.1.1/secure/login',
        'https://bit.ly/suspicious-link',
        'http://facebook-security.ml/confirm',
        'https://google-verification.click/signin',
        'http://secure-banking-update.download/login',
        'https://account-suspended.link/restore',
        'http://microsoft-support.cf/secure',
        'https://paypal.verification-security.tk',
        'http://amazon.security-check.ml/account',
        'https://facebook.account-verify.ga/login',
        'http://google-security-alert.click/signin',
        'https://banking-security-update.download',
        'http://account-verification-required.link'
    ]
    
    urls = benign_urls + phishing_urls
    labels = ['benign'] * len(benign_urls) + ['phishing'] * len(phishing_urls)
    
    return pd.DataFrame({'url': urls, 'label': labels})


if __name__ == "__main__":
    # Initialize detector
    detector = PhishingDetector()
    
    # Try to load existing model
    if not detector.load_model():
        print("No existing model found. Training new model...")
        
        # Load or create training data
        try:
            df = pd.read_csv('url_data.csv')
            print(f"Loaded {len(df)} URLs from url_data.csv")
        except FileNotFoundError:
            print("url_data.csv not found. Creating sample dataset...")
            df = create_sample_data()
            df.to_csv('enhanced_url_data.csv', index=False)
            print(f"Created sample dataset with {len(df)} URLs")
        
        # Train model
        accuracy = detector.train_model(df)
        
        # Save model
        detector.save_model()
    
    # Test the model
    test_urls = [
        'https://www.google.com',
        'http://paypal-security.tk/signin',
        'https://amazon-verification.click/account'
    ]
    
    print("\n" + "="*50)
    print("Testing the model:")
    print("="*50)
    
    for url in test_urls:
        result = detector.predict_url(url)
        print(f"\nURL: {url}")
        print(f"Prediction: {result['prediction']}")
        print(f"Confidence: {result['confidence']:.2f}%")
        print(f"Phishing Probability: {result['probability_phishing']:.2f}%")
