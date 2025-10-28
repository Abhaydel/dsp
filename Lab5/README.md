# Phishing URL Detector

A minimal yet powerful phishing website detection system built with Python and Streamlit, inspired by advanced machine learning research.

## Features

### 🔍 17 Advanced Features Analysis
The system analyzes URLs using 17 carefully selected features across 3 categories:

#### Address Bar Based Features (9 features)
- URL Length
- HTTPS Usage
- Presence of @ symbol
- Double slash in path
- Dash in domain
- Number of subdomains
- URL depth (path levels)
- Suspicious keywords count
- Hostname length

#### Domain Based Features (4 features)
- IP address instead of domain
- Well-known domain detection
- Number of dots in domain
- Numbers in domain

#### HTML & JavaScript Based Features (4 features)
- URL shortening service usage
- Suspicious TLD detection
- Query parameters count
- Special characters count

### 🎯 Machine Learning Model
- **Algorithm**: Random Forest Classifier
- **Training**: 80/20 split
- **Performance**: ~100% accuracy on sample dataset
- **Features**: 17 extracted features per URL

### 🖥️ Streamlit Web Interface
- **Real-time Analysis**: Instant URL checking
- **Visual Results**: Risk gauge and probability breakdown
- **Feature Analysis**: Detailed breakdown of all 17 features
- **Sample Testing**: Pre-loaded safe and suspicious URLs
- **Responsive Design**: Works on desktop and mobile

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Train the Model (Optional)
```bash
python enhanced_phishing_detector.py
```

### 3. Launch Web Interface
```bash
streamlit run streamlit_app.py
```

### 4. Open Browser
Navigate to `http://localhost:8501`

## Usage

1. **Enter URL**: Input any URL in the text field
2. **Click Analyze**: Press the analyze button
3. **View Results**: See prediction, confidence, and detailed analysis
4. **Feature Breakdown**: Review all 17 features that influenced the decision

## Project Structure

```
Lab5/
├── enhanced_phishing_detector.py  # Core ML model and feature extraction
├── streamlit_app.py              # Web interface
├── url_data.csv                  # Training dataset
├── requirements.txt              # Dependencies
├── phishing_model.pkl           # Trained model (generated)
└── README.md                    # Documentation
```

## Sample URLs for Testing

### Safe URLs
- https://www.google.com
- https://www.microsoft.com
- https://www.github.com

### Suspicious URLs
- http://paypal-security.tk/signin
- http://192.168.1.1/secure/login
- https://amazon-verification.click

## Technical Details

### Feature Engineering
The system extracts features that are commonly associated with phishing attempts:

- **Length-based**: Phishing URLs often use longer domains
- **Security**: Legitimate sites typically use HTTPS
- **Structure**: Suspicious patterns like IP addresses, excessive subdomains
- **Keywords**: Common phishing terms like "secure", "verify", "account"
- **TLD Analysis**: Suspicious top-level domains often used in phishing

### Model Training
```python
# Example usage
detector = PhishingDetector()
detector.train_model(training_data)
result = detector.predict_url("https://example.com")
```

## Educational Purpose

This project is designed for:
- **Learning**: Understanding phishing detection techniques
- **Research**: Experimenting with URL analysis features
- **Demonstration**: Showing practical ML applications in cybersecurity

## Future Enhancements

1. **Real-time WHOIS**: Domain registration analysis
2. **Content Analysis**: HTML/JavaScript inspection
3. **Reputation Scoring**: Integration with threat intelligence
4. **Browser Extension**: Real-time protection
5. **API Endpoint**: REST API for integration

## Acknowledgments

Inspired by the research project: [Phishing Website Detection](https://github.com/gangeshbaskerr/Phishing-Website-Detection) which uses advanced machine learning techniques for phishing detection.

## License

This project is for educational purposes only. Always exercise caution when visiting unknown URLs.

---

**⚠️ Disclaimer**: This tool is for educational and research purposes. It should not be relied upon as the sole method for detecting phishing websites. Always exercise caution and use additional security measures.
