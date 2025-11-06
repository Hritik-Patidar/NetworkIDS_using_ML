# ==========================================
# 🧩 Step 0: Import Libraries
# ==========================================
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# ==========================================
# 📂 Step 1: Load Dataset
# ==========================================
df = pd.read_csv("../intrusion_data/Train_data.csv")
print("✅ Data loaded successfully!")
print("Shape:", df.shape)

# ==========================================
# ✂️ Step 2: Select Scapy-Compatible Features
# ==========================================
scapy_columns = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'count', 'srv_count',
    'same_srv_rate', 'diff_srv_rate', 'class'
]

# Remove columns not available in your dataset
df = df[[c for c in scapy_columns if c in df.columns]]
print("✅ Using columns:", df.columns.tolist())

# ==========================================
# 🧹 Step 3: Encode Categorical Columns
# ==========================================
categorical_cols = [col for col in ['protocol_type', 'service', 'flag', 'class'] if col in df.columns]
encoder = LabelEncoder()

for col in categorical_cols:
    df[col] = encoder.fit_transform(df[col])

print("\n✅ Categorical columns encoded.")

# ==========================================
# ✂️ Step 4: Split Data (80% Train, 20% Test)
# ==========================================
X = df.drop("class", axis=1)
y = df["class"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("\n📊 Split complete:")
print("Training samples:", X_train.shape[0])
print("Testing samples:", X_test.shape[0])

# ==========================================
# 🧠 Step 5: Train the Model
# ==========================================
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

print("\n🎯 Model training complete!")

# ==========================================
# 🔍 Step 6: Evaluate Model
# ==========================================
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print("\n✅ Accuracy:", accuracy)
print("\n📈 Classification Report:\n", classification_report(y_test, y_pred))
print("\n🧮 Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# ==========================================
# 💾 Step 7: Save the Model
# ==========================================
joblib.dump(model, "nids_scapy_model.pkl")
print("\n💾 Model saved as nids_scapy_model.pkl")

