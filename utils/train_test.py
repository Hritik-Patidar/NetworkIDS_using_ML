# ==========================================
# 🧩 Step 0: Import Libraries
# ==========================================
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import joblib

# ==========================================
# 📂 Step 1: Load Datasets
# ==========================================
train_df = pd.read_csv("../intrusion_data/Train_data.csv")
test_df = pd.read_csv("../intrusion_data/Test_data.csv")

print("✅ Train shape:", train_df.shape)
print("✅ Test shape:", test_df.shape)

# ==========================================
# 🧹 Step 2: Encode Categorical Columns
# ==========================================
# Sirf features ke text columns encode karenge
categorical_cols = ['protocol_type', 'service', 'flag']

encoder = LabelEncoder()
for col in categorical_cols:
    train_df[col] = encoder.fit_transform(train_df[col])
    test_df[col] = encoder.fit_transform(test_df[col])

# Encode target (class) separately
train_df['class'] = LabelEncoder().fit_transform(train_df['class'])

# ==========================================
# ✂️ Step 3: Split Features and Target
# ==========================================
X_train = train_df.drop("class", axis=1)
y_train = train_df["class"]

X_test = test_df  # test me class column nahi hai

# ==========================================
# 🧠 Step 4: Train the Model
# ==========================================
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

print("🎯 Model training complete!")

# ==========================================
# 🔮 Step 5: Predict on Test Data
# ==========================================
y_pred = model.predict(X_test)
print("✅ Predictions generated:", len(y_pred))

# ==========================================
# 💾 Step 6: Save Results & Model
# ==========================================
# Save predictions with index
pred_df = pd.DataFrame({
    "Prediction": y_pred
})
pred_df["Prediction"] = pred_df["Prediction"].map({0: "normal", 1: "anomaly"})  # convert back to text
pred_df.to_csv("Predicted_Results.csv", index=False)

joblib.dump(model, "nids_model.pkl")
print("💾 Model saved as nids_model.pkl")
print("📄 Predictions saved in Predicted_Results.csv")
