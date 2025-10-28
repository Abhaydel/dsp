import pandas as pd
from urllib.parse import urlparse
import re
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# --- 1. Data Loading and Preparation ---


# Load the dataset from a local CSV file
# This dataset contains two columns: 'url' and 'label' (benign or phishing)
try:
    df = pd.read_csv('url_data.csv')
except Exception as e:
    print(f"Error loading dataset: {e}")
    print("Please ensure the file 'url_data.csv' exists in the current directory.")
    exit()

print("Dataset loaded successfully.")
print("First 5 rows of the dataset:")
print(df.head())
print("\nDataset information:")
df.info()


# --- 2. Feature Engineering ---

# This function extracts features from a URL
def extract_features(url):
    features = {}

    # Feature 1: URL Length
    features['url_length'] = len(url)

    # Feature 2: Presence of 'https'
    features['uses_https'] = 1 if urlparse(url).scheme == 'https' else 0

    # Feature 3: Presence of '@' symbol
    features['contains_at'] = 1 if '@' in url else 0

    # Feature 4: Hostname Length
    hostname = urlparse(url).netloc
    features['hostname_length'] = len(hostname)

    # Feature 5: Number of dots
    features['dot_count'] = url.count('.')

    # Feature 6: Number of hyphens
    features['hyphen_count'] = url.count('-')

    # Feature 7: Number of digits in the URL
    features['digit_count'] = sum(c.isdigit() for c in url)

    # Feature 8: Does it use a shortening service? (simple check)
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|zpr\.io|hol\.es|dot\.tk|" \
                          r"flic\.kr|v\.gd|qr\.net|1url\.com|tweez\.me|v\.sv|alt\.ir|idek\.net|scrnch\.me|filoops\.info"
    features['uses_shortening_service'] = 1 if re.search(
        shortening_services, url) else 0

    return features


print("\nExtracting features from URLs...")
# Apply the function to each URL in the dataframe
features_df = df['url'].apply(lambda url: pd.Series(extract_features(url)))

# Combine the extracted features with the original dataframe
df = pd.concat([df, features_df], axis=1)

print("Features extracted successfully.")
print("First 5 rows of the dataset with features:")
print(df.head())


# --- 3. Model Training ---

# Define features (X) and target (y)
# The target 'label' is categorical ('benign', 'phishing'), so we convert it to numerical (0, 1)
X = df.drop(['url', 'label'], axis=1)
y = df['label'].map({'benign': 0, 'phishing': 1})

# Split the data into training and testing sets (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

print(f"\nTraining data shape: {X_train.shape}")
print(f"Testing data shape: {X_test.shape}")

# Initialize and train the Random Forest Classifier
print("\nTraining the model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
print("Model training complete.")


# --- 4. Model Evaluation ---

# Make predictions on the test set
print("\nEvaluating the model...")
y_pred = model.predict(X_test)

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"\nModel Accuracy: {accuracy * 100:.2f}%")

# Display the classification report
print("\nClassification Report:")
print(classification_report(y_test, y_pred,
      target_names=['Benign', 'Phishing']))
