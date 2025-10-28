import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from enhanced_phishing_detector import PhishingDetector
import time
import re
from urllib.parse import urlparse


# Configure page
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .safe-url {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 5px;
        padding: 10px;
        color: #155724;
    }
    .dangerous-url {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 5px;
        padding: 10px;
        color: #721c24;
    }
    .feature-box {
        background-color: #f8f9fa;
        border-radius: 5px;
        padding: 15px;
        margin: 10px 0;
        border-left: 4px solid #007bff;
        color: #000000 !important;
    }
    .feature-box b {
        color: #000000 !important;
    }
    .feature-box * {
        color: #000000 !important;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'detector' not in st.session_state:
    st.session_state.detector = None
    st.session_state.model_loaded = False


@st.cache_resource
def load_detector():
    """Load the phishing detector model"""
    detector = PhishingDetector()

    # Try to load existing model, otherwise train a new one
    if not detector.load_model():
        st.info("Training new model... This may take a moment.")

        # Create sample data for training
        from enhanced_phishing_detector import create_sample_data
        df = create_sample_data()

        # Train model
        detector.train_model(df)
        detector.save_model()
        st.success("Model trained and saved successfully!")

    return detector


def validate_url(url):
    """Validate if the input is a proper URL"""
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        # domain...
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return url_pattern.match(url) is not None


def display_feature_analysis(features):
    """Display detailed feature analysis"""
    st.subheader("🔍 Feature Analysis")

    # Create two columns for features
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Address Bar Features")
        st.markdown(f"""
        <div class="feature-box">
        <b>URL Length:</b> {features['url_length']} characters<br>
        <b>Uses HTTPS:</b> {'Yes' if features['uses_https'] else 'No'}<br>
        <b>Contains @ symbol:</b> {'Yes' if features['contains_at'] else 'No'}<br>
        <b>Double slash in path:</b> {'Yes' if features['double_slash_path'] else 'No'}<br>
        <b>Dash in domain:</b> {'Yes' if features['dash_in_domain'] else 'No'}
        </div>
        """, unsafe_allow_html=True)

        st.markdown("### Domain Features")
        st.markdown(f"""
        <div class="feature-box">
        <b>Hostname Length:</b> {features['hostname_length']} characters<br>
        <b>Subdomain Count:</b> {features['subdomain_count']}<br>
        <b>Contains IP:</b> {'Yes' if features['contains_ip'] else 'No'}<br>
        <b>Well-known Domain:</b> {'Yes' if features['well_known_domain'] else 'No'}<br>
        <b>Dots in Domain:</b> {features['dots_in_domain']}
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("### Suspicious Indicators")
        st.markdown(f"""
        <div class="feature-box">
        <b>URL Depth:</b> {features['url_depth']} levels<br>
        <b>Suspicious Keywords:</b> {features['suspicious_keywords']} found<br>
        <b>Uses URL Shortening:</b> {'Yes' if features['uses_shortening'] else 'No'}<br>
        <b>Suspicious TLD:</b> {'Yes' if features['suspicious_tld'] else 'No'}<br>
        <b>Special Characters:</b> {features['special_chars_count']} count
        </div>
        """, unsafe_allow_html=True)

        st.markdown("### Additional Features")
        st.markdown(f"""
        <div class="feature-box">
        <b>Numbers in Domain:</b> {'Yes' if features['numbers_in_domain'] else 'No'}<br>
        <b>Query Parameters:</b> {features['query_params']} count<br>
        </div>
        """, unsafe_allow_html=True)


def create_risk_gauge(probability):
    """Create a risk gauge visualization"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=probability,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Phishing Risk %"},
        delta={'reference': 50},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 25], 'color': "lightgreen"},
                {'range': [25, 50], 'color': "yellow"},
                {'range': [50, 75], 'color': "orange"},
                {'range': [75, 100], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))

    fig.update_layout(height=300)
    return fig


def main():
    # Header
    st.markdown('<h1 class="main-header">🛡️ Phishing URL Detector</h1>',
                unsafe_allow_html=True)

    # Description
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
    <p style="font-size: 1.2rem; color: #666;">
    Advanced machine learning-powered detection system to identify phishing websites.
    Enter a URL below to check if it's safe or potentially dangerous.
    </p>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar
    with st.sidebar:
        st.header("ℹ️ About")
        st.write("""
        This tool uses machine learning to analyze 17 different features of a URL to determine if it's likely to be a phishing site.
        
        **Features analyzed:**
        - URL structure and length
        - Domain characteristics
        - Security indicators
        - Suspicious patterns
        """)

        st.header("📊 Model Info")
        if st.session_state.detector:
            st.success("✅ Model Loaded")
            st.write("Algorithm: Random Forest")
            st.write("Features: 17 extracted features")
        else:
            st.warning("⏳ Loading model...")

    # Load detector
    if not st.session_state.model_loaded:
        with st.spinner("Loading phishing detection model..."):
            st.session_state.detector = load_detector()
            st.session_state.model_loaded = True

    # Main input section
    st.header("🔍 URL Analysis")

    # URL input
    url_input = st.text_input(
        "Enter URL to analyze:",
        placeholder="https://example.com",
        help="Enter a complete URL including http:// or https://"
    )

    # Analysis button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        analyze_button = st.button(
            "🔍 Analyze URL", type="primary", use_container_width=True)

    if analyze_button and url_input:
        if not validate_url(url_input):
            st.error("❌ Please enter a valid URL (including http:// or https://)")
            return

        with st.spinner("Analyzing URL..."):
            try:
                # Add a small delay for better UX
                time.sleep(0.5)

                # Get prediction
                result = st.session_state.detector.predict_url(url_input)

                # Display results
                st.header("📋 Analysis Results")

                # Main result display
                col1, col2 = st.columns([1, 1])

                with col1:
                    if result['prediction'] == 'Benign':
                        st.markdown(f"""
                        <div class="safe-url">
                        <h3>✅ SAFE URL</h3>
                        <p><strong>Prediction:</strong> {result['prediction']}</p>
                        <p><strong>Confidence:</strong> {result['confidence']:.2f}%</p>
                        <p>This URL appears to be legitimate and safe to visit.</p>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div class="dangerous-url">
                        <h3>⚠️ POTENTIAL PHISHING</h3>
                        <p><strong>Prediction:</strong> {result['prediction']}</p>
                        <p><strong>Confidence:</strong> {result['confidence']:.2f}%</p>
                        <p>This URL shows characteristics of a phishing site. Exercise caution!</p>
                        </div>
                        """, unsafe_allow_html=True)

                with col2:
                    # Risk gauge
                    fig = create_risk_gauge(result['probability_phishing'])
                    st.plotly_chart(fig, use_container_width=True)

                # Probability breakdown
                st.subheader("📊 Probability Breakdown")
                prob_col1, prob_col2 = st.columns(2)

                with prob_col1:
                    st.metric("🟢 Benign Probability",
                              f"{result['probability_benign']:.2f}%")

                with prob_col2:
                    st.metric("🔴 Phishing Probability",
                              f"{result['probability_phishing']:.2f}%")

                # Feature analysis
                display_feature_analysis(result['features'])

                # URL breakdown
                st.subheader("🔗 URL Breakdown")
                parsed = urlparse(url_input)
                breakdown_col1, breakdown_col2 = st.columns(2)

                with breakdown_col1:
                    st.write(f"**Scheme:** {parsed.scheme}")
                    st.write(f"**Domain:** {parsed.netloc}")
                    st.write(f"**Path:** {parsed.path or '/'}")

                with breakdown_col2:
                    st.write(f"**Query:** {parsed.query or 'None'}")
                    st.write(f"**Fragment:** {parsed.fragment or 'None'}")
                    st.write(f"**Port:** {parsed.port or 'Default'}")

            except Exception as e:
                st.error(f"❌ Error analyzing URL: {str(e)}")

    # Sample URLs for testing
    st.header("🧪 Test with Sample URLs")
    st.write("Click on any sample URL to test the detector:")

    sample_col1, sample_col2 = st.columns(2)

    with sample_col1:
        st.subheader("✅ Safe URLs")
        safe_urls = [
            "https://www.google.com",
            "https://www.microsoft.com",
            "https://www.github.com"
        ]
        for url in safe_urls:
            if st.button(url, key=f"safe_{url}"):
                st.session_state.url_input = url
                st.rerun()

    with sample_col2:
        st.subheader("⚠️ Suspicious URLs")
        suspicious_urls = [
            "http://paypal-security.tk/signin",
            "http://192.168.1.1/secure/login",
            "https://amazon-verification.click"
        ]
        for url in suspicious_urls:
            if st.button(url, key=f"suspicious_{url}"):
                st.session_state.url_input = url
                st.rerun()

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; margin-top: 2rem;">
    <p>🛡️ Phishing URL Detector | Built with Streamlit & Machine Learning</p>
    <p><small>This tool is for educational purposes. Always exercise caution when visiting unknown URLs.</small></p>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
