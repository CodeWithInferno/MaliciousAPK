#!/usr/bin/env python3
import pandas as pd

def feature_engineering(input_file, output_file):
    # Load the cleaned CSV file
    df = pd.read_csv(input_file)
    
    # 1. SDK Gap: Difference between target_sdk and min_sdk.
    # A larger gap may indicate an app is built for modern devices but still supports older, less secure APIs.
    df['sdk_gap'] = df['target_sdk'] - df['min_sdk']
    
    # 2. Total Permission Count: Number of permissions requested.
    # More permissions might correlate with increased functionality or risk.
    df['total_permission_count'] = df['permissions'].apply(
        lambda x: len(x.split(',')) if isinstance(x, str) and x.strip() != '' else 0
    )
    
    # 3. Sensitive Permission Count: Count of high-risk permissions.
    # Sensitive permissions include those that affect user privacy and security.
    sensitive_perms = [
        'android.permission.RECEIVE_SMS', 'android.permission.SEND_SMS',
        'android.permission.READ_SMS', 'android.permission.WRITE_SMS',
        'android.permission.CALL_PHONE', 'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.READ_PHONE_STATE'
    ]
    df['sensitive_perm_count'] = df['permissions'].apply(
        lambda x: sum(1 for perm in x.split(',') if perm.strip() in sensitive_perms) if isinstance(x, str) else 0
    )
    
    # 4. Permission Risk Ratio: Sensitive permissions normalized by the total permissions.
    # This feature captures the proportion of permissions that are risky.
    df['permission_risk_ratio'] = df.apply(
        lambda row: row['sensitive_perm_count'] / row['total_permission_count']
        if row['total_permission_count'] > 0 else 0, axis=1
    )
    
    # 5. Background Components Total: Sum of services and receivers.
    # Apps with many background components might be doing more hidden processing.
    df['bg_component_total'] = df['services_count'] + df['receivers_count']
    
    # 6. Component Ratio: Ratio of background components to activities.
    # A high ratio suggests more background processing relative to user-facing components.
    df['component_ratio'] = df.apply(
        lambda row: row['bg_component_total'] / (row['activities_count'] if row['activities_count'] > 0 else 1), axis=1
    )
    
    # 7. Low SDK Flag: Flag if min_sdk is below a threshold (e.g., 10).
    # Low min_sdk might indicate compatibility with older, vulnerable Android versions.
    df['low_sdk_flag'] = (df['min_sdk'] < 10).astype(int)
    
    # 8. Interaction Feature: Low SDK and high API calls.
    # Flags apps with low min_sdk and above-median API calls, which could indicate risky behavior.
    df['low_sdk_high_api'] = (
        (df['min_sdk'] < 10).astype(int) *
        (df['api_calls_count'] > df['api_calls_count'].median()).astype(int)
    )
    
    # 9. Normalized API Calls: API calls per version code (as a proxy for app complexity relative to version).
    df['normalized_api_calls'] = df.apply(
        lambda row: row['api_calls_count'] / (row['version_code'] if row['version_code'] != 0 else 1), axis=1
    )
    
    # Save the feature engineered DataFrame to a new CSV
    df.to_csv(output_file, index=False)
    print(f"Feature engineered data saved to {output_file}")

if __name__ == '__main__':
    input_path = '/home/john/MaliciousAPKDetection/Output/Try2/static_features_cleaned.csv'
    output_path = '/home/john/MaliciousAPKDetection/Output/Try2/static_features_engineered.csv'
    feature_engineering(input_path, output_path)
