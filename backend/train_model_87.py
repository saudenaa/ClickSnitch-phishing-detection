import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.utils import resample

from extract_features_from_url import extract_features_from_url

# --------------------------
# Load dataset
# --------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
dataset_path = os.path.join(BASE_DIR, '..', 'dataset', 'dataset_phishing.csv')

df = pd.read_csv(dataset_path)

if "url" not in df.columns or "status" not in df.columns:
    raise Exception("Dataset MUST contain 'url' and 'status' columns")

print("Loaded dataset with:", len(df), "rows")

# Normalize labels
df["status"] = df["status"].str.lower().str.strip()

# --------------------------
# Extract 87 features for each URL
# --------------------------
feature_rows = []
labels = []

print("Extracting features... this may take time")

for i, row in df.iterrows():
    url = str(row["url"])
    label = row["status"]

    feats = extract_features_from_url(url)
    feature_rows.append(feats)
    labels.append(label)

feature_df = pd.DataFrame(feature_rows)
feature_df["status"] = labels

print("Feature DF shape:", feature_df.shape)
print("Columns:", feature_df.columns)

# --------------------------
# Balance dataset
# --------------------------
phish = feature_df[feature_df["status"] == "phishing"]
legit = feature_df[feature_df["status"] == "legitimate"]

phish_down = resample(phish, replace=False, n_samples=len(legit), random_state=42)
balanced = pd.concat([phish_down, legit])

print("Balanced DF:", balanced["status"].value_counts())

# --------------------------
# Train/Test split
# --------------------------
X = balanced.drop("status", axis=1)
y = balanced["status"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# --------------------------
# Train RandomForest
# --------------------------
model = RandomForestClassifier()
model.fit(X_train, y_train)

pred = model.predict(X_test)
acc = accuracy_score(y_test, pred)

print("Model Accuracy:", acc)

# --------------------------
# Save model & feature names
# --------------------------
joblib.dump(model, "phishing_model.pkl")
joblib.dump(list(X.columns), "feature_names.pkl")

print("Model saved as phishing_model.pkl")
print("Feature list saved as feature_names.pkl")
print("Training completed successfully ✔")
