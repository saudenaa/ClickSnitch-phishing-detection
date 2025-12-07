from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from extract_features_from_url import extract_features_from_url

app = Flask(__name__)
CORS(app)

# Load correct model
model = joblib.load("phishing_model.pkl")

# Load NEW correct feature order
model_features = joblib.load("feature_names.pkl")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        url = data.get("url", "")

        if not url:
            return jsonify({"result": "error", "details": "URL not provided"}), 400

        feats = extract_features_from_url(url)
        df = pd.DataFrame([feats])

        # VERY IMPORTANT: enforce correct feature order
        df = df[model_features]

        prediction = model.predict(df)[0]
        return jsonify({"result": prediction})

    except Exception as e:
        print("BACKEND ERROR:", e)
        return jsonify({"result": "error", "details": str(e)}), 500


@app.route("/")
def home():
    return "ClickSnitch API is running with the correct 87-feature model!"

if __name__ == "__main__":
    print("🚀 Starting backend at http://127.0.0.1:5000")
    app.run(debug=True)
