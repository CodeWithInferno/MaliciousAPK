#!/usr/bin/env python3
import pandas as pd

def clean_data(input_file, output_file):
    # Read the CSV file into a DataFrame
    df = pd.read_csv(input_file)
    print("Original Data Preview:")
    print(df.head())
    
    # Standardize column names (trim whitespace)
    df.columns = [col.strip() for col in df.columns]

    # Clean text fields: strip extra spaces
    text_fields = ['apk_name', 'package_name', 'version_name', 'permissions', 'certificate_issuer']
    for field in text_fields:
        if field in df.columns:
            df[field] = df[field].astype(str).str.strip()
    
    # Remove duplicate rows
    df = df.drop_duplicates()

    # Fill missing values in the permissions field with an empty string
    if 'permissions' in df.columns:
        df['permissions'] = df['permissions'].fillna('')

    # Ensure numeric fields are numeric and clean up non-numeric entries
    numeric_fields = [
        'min_sdk', 'target_sdk', 'version_code', 
        'activities_count', 'services_count', 'receivers_count', 
        'api_calls_count', 'obfuscation_score', 'is_benign'
    ]
    for field in numeric_fields:
        if field in df.columns:
            df[field] = pd.to_numeric(df[field], errors='coerce')
    
    # Optionally, drop rows with missing critical numeric values
    df = df.dropna(subset=numeric_fields)
    
    # Reset index after dropping rows
    df = df.reset_index(drop=True)

    # Write the cleaned DataFrame to a new CSV file
    df.to_csv(output_file, index=False)
    print(f"Cleaned data saved to {output_file}")

if __name__ == '__main__':
    input_path = '/home/john/MaliciousAPKDetection/Output/Try2/static_features.csv'
    output_path = '/home/john/MaliciousAPKDetection/Output/Try2/static_features_cleaned.csv'
    clean_data(input_path, output_path)
