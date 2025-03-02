import pandas as pd
import ast
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pickle

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, learning_curve
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, auc

def main():
    # 1. Load the CSV file
    csv_path = "/home/john/MaliciousAPKDetection/Output/Dynamic/malware_data.csv"
    df = pd.read_csv(csv_path)

    # 2. Convert JSON-like string columns to actual Python objects
    df['Permissions Analysis'] = df['Permissions Analysis'].apply(ast.literal_eval)
    df['API Calls'] = df['API Calls'].apply(ast.literal_eval)
    df['Suspicious Logs'] = df['Suspicious Logs'].apply(ast.literal_eval)

    # 3. Extract features:
    #    - dangerous_count: count of dangerous permissions
    #    - total_permissions: total permissions count from the 'total' key
    #    - total_api_calls: sum of all API call counts
    #    - suspicious_logs_count: count of suspicious logs
    df['dangerous_count'] = df['Permissions Analysis'].apply(lambda d: len(d.get('dangerous', [])))
    df['total_permissions'] = df['Permissions Analysis'].apply(lambda d: d.get('total', 0))
    df['total_api_calls'] = df['API Calls'].apply(lambda d: sum(d.values()))
    df['suspicious_logs_count'] = df['Suspicious Logs'].apply(lambda lst: len(lst))

    # Convert Battery Drain and CPU Usage to numeric values
    df['Battery Drain'] = pd.to_numeric(df['Battery Drain'], errors='coerce')
    df['CPU Usage'] = pd.to_numeric(df['CPU Usage'], errors='coerce')

    # Drop rows with missing values in our features, if any
    df.dropna(subset=['dangerous_count', 'total_permissions', 'total_api_calls',
                      'suspicious_logs_count', 'Battery Drain', 'CPU Usage'], inplace=True)

    # 4. Prepare feature matrix X and label vector y
    feature_cols = ['dangerous_count', 'total_permissions', 'total_api_calls', 
                    'suspicious_logs_count', 'Battery Drain', 'CPU Usage']
    X = df[feature_cols]
    # The malware label is assumed to be in the 'Malware (Label)' column (1 = malicious, 0 = benign)
    y = df['Malware (Label)']

    # 5. Split the dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # 6. Train a Random Forest classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    # 7. Evaluate the model on the test set
    y_pred = clf.predict(X_test)
    print("Classification Report:")
    print(classification_report(y_test, y_pred))

    # 8A. Plot and save Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", 
                xticklabels=["Benign", "Malicious"], yticklabels=["Benign", "Malicious"])
    plt.ylabel("Actual")
    plt.xlabel("Predicted")
    plt.title("Confusion Matrix")
    plt.tight_layout()
    plt.savefig("confusion_matrix.png")
    plt.show()
    plt.close()

    # 8B. Plot and save ROC Curve
    y_probs = clf.predict_proba(X_test)[:, 1]
    fpr, tpr, thresholds = roc_curve(y_test, y_probs)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(6,5))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label="ROC curve (area = %0.2f)" % roc_auc)
    plt.plot([0,1], [0,1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0,1.0])
    plt.ylim([0.0,1.05])
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Receiver Operating Characteristic (ROC) Curve")
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig("roc_curve.png")
    plt.show()
    plt.close()

    # 8C. Plot and save Learning Curve to show training dynamics
    train_sizes, train_scores, test_scores = learning_curve(clf, X, y, cv=5, 
                                                            scoring='accuracy', n_jobs=-1, 
                                                            train_sizes=np.linspace(0.1, 1.0, 10))
    train_scores_mean = np.mean(train_scores, axis=1)
    train_scores_std = np.std(train_scores, axis=1)
    test_scores_mean = np.mean(test_scores, axis=1)
    test_scores_std = np.std(test_scores, axis=1)

    plt.figure(figsize=(8,6))
    plt.fill_between(train_sizes, train_scores_mean - train_scores_std,
                     train_scores_mean + train_scores_std, alpha=0.1, color="r")
    plt.fill_between(train_sizes, test_scores_mean - test_scores_std,
                     test_scores_mean + test_scores_std, alpha=0.1, color="g")
    plt.plot(train_sizes, train_scores_mean, 'o-', color="r", label="Training Score")
    plt.plot(train_sizes, test_scores_mean, 'o-', color="g", label="CV Score")
    plt.title("Learning Curve")
    plt.xlabel("Training Examples")
    plt.ylabel("Accuracy")
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig("learning_curve.png")
    plt.show()
    plt.close()

    # 8D. Plot and save Feature Importances from the trained model
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]
    plt.figure(figsize=(8,6))
    plt.title("Feature Importances")
    plt.bar(range(len(feature_cols)), importances[indices], align="center")
    plt.xticks(range(len(feature_cols)), [feature_cols[i] for i in indices], rotation=45)
    plt.tight_layout()
    plt.savefig("feature_importances.png")
    plt.show()
    plt.close()

    # 9. Save the trained model to disk using pickle
    model_filename = "random_forest_model.pkl"
    with open(model_filename, "wb") as f:
        pickle.dump(clf, f)
    print(f"Model saved to {model_filename}")

if __name__ == "__main__":
    main()
