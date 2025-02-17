#!/usr/bin/env python3
import pandas as pd
import joblib

def extract_features(apk_path):
    """
    Dummy function to simulate feature extraction from an APK.
    In a real scenario, this function would parse the APK file and
    extract the necessary features.
    
    Returns a dictionary with the following keys:
      - min_sdk, target_sdk, version_code, api_calls_count, obfuscation_score,
      - sdk_gap, total_permission_count, sensitive_perm_count,
      - bg_component_total, low_sdk_high_api
    """
    # Simulated raw features (replace with actual extraction logic)
    features = {
        'min_sdk': 8,
        'target_sdk': 23,
        'version_code': 50,
        'api_calls_count': 5000,
        'obfuscation_score': 0
    }
    
    # Compute engineered features
    features['sdk_gap'] = features['target_sdk'] - features['min_sdk']
    
    # Simulated permissions string extracted from the APK
    permissions_str = "android.permission.INTERNET, android.permission.ACCESS_NETWORK_STATE, android.permission.RECEIVE_SMS, android.permission.SEND_SMS"
    
    # Total permission count
    perm_list = [p.strip() for p in permissions_str.split(',')]
    features['total_permission_count'] = len(perm_list)
    
    # Count sensitive permissions
    sensitive_perms = [
        'android.permission.RECEIVE_SMS', 'android.permission.SEND_SMS',
        'android.permission.READ_SMS', 'android.permission.WRITE_SMS',
        'android.permission.CALL_PHONE', 'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.READ_PHONE_STATE'
    ]
    features['sensitive_perm_count'] = sum(1 for perm in perm_list if perm in sensitive_perms)
    
    # Simulated component counts (you would extract these from the APK)
    services_count = 5
    receivers_count = 4
    features['bg_component_total'] = services_count + receivers_count
    
    # Interaction feature: flag if min_sdk < 10 and api_calls_count above a threshold (assumed median, e.g., 4000)
    features['low_sdk_high_api'] = 1 if (features['min_sdk'] < 10 and features['api_calls_count'] > 4000) else 0
    
    return features

def main():
    # APK to test and model path
    apk_path = '/home/john/MaliciousAPKDetection/854774a198db490a1ae9f06d5da5fe6a1f683bf3d7186e56776516f982d41ad3.apk'
    model_path = '/home/john/MaliciousAPKDetection/Output/random_forest_model.pkl'
    
    # Extract features from the APK
    feature_dict = extract_features(apk_path)
    print("Extracted features:", feature_dict)
    
    # Create a DataFrame for the model. The feature names must match those used during training.
    feature_names = [
        'min_sdk', 'target_sdk', 'version_code', 'api_calls_count', 'obfuscation_score',
        'sdk_gap', 'total_permission_count', 'sensitive_perm_count', 'bg_component_total', 'low_sdk_high_api'
    ]
    X_new = pd.DataFrame([feature_dict], columns=feature_names)
    
    # Load the trained model
    clf = joblib.load(model_path)
    
    # Predict the class (1: benign, 0: malicious) and output probabilities
    prediction = clf.predict(X_new)[0]
    prediction_proba = clf.predict_proba(X_new)[0]
    
    print("Prediction (1: benign, 0: malicious):", prediction)
    print("Prediction probabilities:", prediction_proba)

if __name__ == '__main__':
    main()
