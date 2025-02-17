import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (classification_report, roc_auc_score, 
                             confusion_matrix, roc_curve, auc, 
                             precision_recall_curve, average_precision_score)
import joblib

# Create graphs directory if it doesn't exist
graphs_dir = '/home/john/MaliciousAPKDetection/Output/Graphs'
os.makedirs(graphs_dir, exist_ok=True)

# 1. Load the feature engineered dataset
df = pd.read_csv('/home/john/MaliciousAPKDetection/Output/Try2/static_features_engineered.csv')

# 2. Define your feature columns and target label
features = [
    'min_sdk', 'target_sdk', 'version_code', 'api_calls_count', 'obfuscation_score',
    'sdk_gap', 'total_permission_count', 'sensitive_perm_count', 'bg_component_total', 'low_sdk_high_api'
]
X = df[features]
y = df['is_benign']  # 1 for benign, 0 for malicious

# 3. Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Train a RandomForestClassifier
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# 5. Evaluate the model with standard metrics
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))
roc_auc = roc_auc_score(y_test, clf.predict_proba(X_test)[:, 1])
print("ROC AUC:", roc_auc)

# Cross-validation scores to assess model stability (optional)
cv_scores = cross_val_score(clf, X, y, cv=5)
print("Cross-validation scores:", cv_scores)
print("Mean CV score:", np.mean(cv_scores))

# 6. Save the trained model to disk
model_path = '/home/john/MaliciousAPKDetection/Output/Try2/random_forest_model.pkl'
joblib.dump(clf, model_path)
print(f"Model saved to {model_path}")

# -------------------------------
# Visualization Code Starts Here
# -------------------------------

# a) Confusion Matrix Plot
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.title('Confusion Matrix')
plt.xlabel('Predicted Label')
plt.ylabel('Actual Label')
plt.savefig(os.path.join(graphs_dir, 'confusion_matrix.png'))
plt.close()

# b) ROC Curve Plot
y_pred_prob = clf.predict_proba(X_test)[:, 1]
fpr, tpr, thresholds = roc_curve(y_test, y_pred_prob)
roc_auc_value = auc(fpr, tpr)

plt.figure(figsize=(6, 4))
plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc_value:.2f})')
plt.plot([0, 1], [0, 1], linestyle='--', color='red')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic')
plt.legend(loc='lower right')
plt.savefig(os.path.join(graphs_dir, 'roc_curve.png'))
plt.close()

# c) Feature Importance Plot
importances = clf.feature_importances_
indices = np.argsort(importances)[::-1]  # sort features by importance descending
sorted_features = [features[i] for i in indices]

plt.figure(figsize=(8, 6))
plt.title("Feature Importances")
plt.bar(range(len(features)), importances[indices], align='center')
plt.xticks(range(len(features)), sorted_features, rotation=45)
plt.tight_layout()
plt.savefig(os.path.join(graphs_dir, 'feature_importances.png'))
plt.close()

# d) Precision-Recall Curve Plot (Optional)
precision, recall, thresholds_pr = precision_recall_curve(y_test, y_pred_prob)
avg_precision = average_precision_score(y_test, y_pred_prob)

plt.figure(figsize=(6, 4))
plt.plot(recall, precision, label=f'Precision-Recall (AP = {avg_precision:.2f})')
plt.xlabel('Recall')
plt.ylabel('Precision')
plt.title('Precision-Recall Curve')
plt.legend(loc='lower left')
plt.savefig(os.path.join(graphs_dir, 'precision_recall_curve.png'))
plt.close()
