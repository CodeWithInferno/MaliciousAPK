# import os
# import csv
# import glob
# from multiprocessing import Pool
# from androguard.misc import AnalyzeAPK

# def analyze_apk(apk_path):
#     """Extract basic static features from an APK file"""
#     try:
#         a, d, dx = AnalyzeAPK(apk_path)
        
#         # Get certificate info
#         cert_info = "unknown"
#         try:
#             cert = a.get_certificates()[0]
#             cert_info = cert.issuer.human_friendly
#         except:
#             pass
            
#         # Get API calls
#         api_calls = set()
#         for method in dx.get_methods():
#             for _, call, _ in method.get_xref_to():
#                 if call.class_name.startswith('Landroid'):
#                     api_calls.add(f"{call.class_name}->{call.name}")
                    
#         # Calculate basic obfuscation score (0-100)
#         obf_score = 0
#         try:
#             # Check for short/obfuscated names
#             classes = dx.get_classes()
#             obf_names = sum(1 for c in classes if len(c.name) <= 3)
#             obf_score = min(100, int((obf_names / len(classes)) * 100))
#         except:
#             pass
            
#         features = {
#             'apk_name': os.path.basename(apk_path),
#             'package_name': a.get_package(),
#             'min_sdk': a.get_min_sdk_version(), 
#             'target_sdk': a.get_target_sdk_version(),
#             'version_name': a.get_androidversion_name(),
#             'version_code': a.get_androidversion_code(),
#             'permissions': ','.join(a.get_permissions()),
#             'activities_count': len(a.get_activities()),
#             'services_count': len(a.get_services()),
#             'receivers_count': len(a.get_receivers()),
#             'certificate_issuer': cert_info,
#             'api_calls_count': len(api_calls),
#             'obfuscation_score': obf_score,
#             'is_benign': 1 if 'Benign' in apk_path else 0  # 1 for benign, 0 for malicious
#         }
        
#         return features
    
#     except Exception as e:
#         print(f"Error analyzing {apk_path}: {str(e)}")
#         return None

# def get_processed_apks(csv_path):
#     """Get list of already processed APK names from CSV"""
#     processed = set()
#     if os.path.exists(csv_path):
#         with open(csv_path, 'r') as f:
#             reader = csv.DictReader(f)
#             processed = {row['apk_name'] for row in reader}
#     return processed

# def process_and_save(apk_path, output_csv, processed_apks):
#     """Process single APK and append results to CSV if not already processed"""
#     apk_name = os.path.basename(apk_path)
#     if apk_name in processed_apks:
#         print(f"Skipping {apk_name} - already processed")
#         return
        
#     features = analyze_apk(apk_path)
#     if features:
#         with open(output_csv, 'a', newline='') as csvfile:
#             writer = csv.DictWriter(csvfile, fieldnames=features.keys())
#             writer.writerow(features)
#         print(f"Processed {apk_name}")
#     else:
#         print(f"Failed to process {apk_name}")

# def main():
#     benign_dir = "/home/john/MaliciousAPKDetection/Dataset/Benign/Benign"
#     malicious_dir = "/home/john/MaliciousAPKDetection/Dataset/Malicious/Malicious"
#     output_csv = "/home/john/MaliciousAPKDetection/Output/static_features.csv"
    
#     os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
#     # Get list of already processed APKs
#     processed_apks = get_processed_apks(output_csv)
    
#     # Initialize CSV with headers if it doesn't exist
#     if not os.path.exists(output_csv):
#         sample_features = analyze_apk(glob.glob(os.path.join(benign_dir, "*.apk"))[0])
#         with open(output_csv, 'w', newline='') as csvfile:
#             writer = csv.DictWriter(csvfile, fieldnames=sample_features.keys())
#             writer.writeheader()
    
#     # Process benign APKs first
#     benign_apks = glob.glob(os.path.join(benign_dir, "*.apk"))
#     print(f"\nProcessing benign APKs...")
    
#     with Pool() as pool:
#         pool.starmap(process_and_save, [(apk, output_csv, processed_apks) for apk in benign_apks])
    
#     # Then process malicious APKs
#     malicious_apks = glob.glob(os.path.join(malicious_dir, "*.apk"))
#     print(f"\nProcessing malicious APKs...")
    
#     with Pool() as pool:
#         pool.starmap(process_and_save, [(apk, output_csv, processed_apks) for apk in malicious_apks])
    
#     print(f"\nAnalysis complete. Results saved to {output_csv}")

# if __name__ == "__main__":
#     main()








# #!/usr/bin/env python3
# import os
# import csv
# from androguard.misc import AnalyzeAPK

# def analyze_apk(apk_path):
#     """Extract basic static features from an APK file"""
#     try:
#         a, d, dx = AnalyzeAPK(apk_path)
        
#         # Get certificate info
#         cert_info = "unknown"
#         try:
#             cert = a.get_certificates()[0]
#             cert_info = cert.issuer.human_friendly
#         except Exception as e:
#             pass
            
#         # Get API calls
#         api_calls = set()
#         for method in dx.get_methods():
#             for _, call, _ in method.get_xref_to():
#                 if call.class_name.startswith('Landroid'):
#                     api_calls.add(f"{call.class_name}->{call.name}")
                    
#         # Calculate basic obfuscation score (0-100)
#         obf_score = 0
#         try:
#             classes = dx.get_classes()
#             obf_names = sum(1 for c in classes if len(c.name) <= 3)
#             obf_score = min(100, int((obf_names / len(classes)) * 100))
#         except Exception as e:
#             pass
            
#         features = {
#             'apk_name': os.path.basename(apk_path),
#             'package_name': a.get_package(),
#             'min_sdk': a.get_min_sdk_version(), 
#             'target_sdk': a.get_target_sdk_version(),
#             'version_name': a.get_androidversion_name(),
#             'version_code': a.get_androidversion_code(),
#             'permissions': ','.join(a.get_permissions()),
#             'activities_count': len(a.get_activities()),
#             'services_count': len(a.get_services()),
#             'receivers_count': len(a.get_receivers()),
#             'certificate_issuer': cert_info,
#             'api_calls_count': len(api_calls),
#             'obfuscation_score': obf_score,
#             'is_benign': 1 if 'Benign' in apk_path else 0  # 1 for benign, 0 for malicious
#         }
        
#         return features
    
#     except Exception as e:
#         print(f"Error analyzing {apk_path}: {str(e)}")
#         return None

# def process_single_apk(apk_path, output_csv):
#     """Process a single APK and append the results to the CSV file."""
#     features = analyze_apk(apk_path)
#     if features:
#         print("Extracted features:", features)
#         # Check if the CSV file exists. If not, write header.
#         file_exists = os.path.exists(output_csv)
#         with open(output_csv, 'a', newline='') as csvfile:
#             writer = csv.DictWriter(csvfile, fieldnames=features.keys())
#             if not file_exists:
#                 writer.writeheader()
#             writer.writerow(features)
#         print(f"Processed {os.path.basename(apk_path)} and appended results to {output_csv}")
#     else:
#         print(f"Failed to process {apk_path}")

# def main():
#     # Set the new APK path
#     apk_path = "/home/john/MaliciousAPKDetection/854774a198db490a1ae9f06d5da5fe6a1f683bf3d7186e56776516f982d41ad3.apk"
#     # Set the output CSV file path (using the same file 'static_features.csv')
#     output_csv = "/home/john/MaliciousAPKDetection/Output/static_features.csv"
    
#     process_single_apk(apk_path, output_csv)

# if __name__ == "__main__":
#     main()













import os
import csv
import glob
from multiprocessing import Pool
from androguard.misc import AnalyzeAPK

def analyze_apk(apk_path):
    """Extract basic static features from an APK file"""
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        
        # Get certificate info
        cert_info = "unknown"
        try:
            cert = a.get_certificates()[0]
            cert_info = cert.issuer.human_friendly
        except:
            pass
            
        # Get API calls
        api_calls = set()
        for method in dx.get_methods():
            for _, call, _ in method.get_xref_to():
                if call.class_name.startswith('Landroid'):
                    api_calls.add(f"{call.class_name}->{call.name}")
                    
        # Calculate basic obfuscation score (0-100)
        obf_score = 0
        try:
            # Fix: For each class, remove leading 'L' and trailing ';' and check final name length
            classes = dx.get_classes()
            if classes:
                obf_names = 0
                for c in classes:
                    raw_name = c.name  # e.g. Lcom/example/MyClass;
                    if raw_name.startswith('L'):
                        raw_name = raw_name[1:]
                    if raw_name.endswith(';'):
                        raw_name = raw_name[:-1]
                    # Get the actual class name (last part after '/')
                    short_name = raw_name.split('/')[-1]
                    if len(short_name) <= 3:
                        obf_names += 1
                obf_score = min(100, int((obf_names / len(classes)) * 100))
        except:
            pass
            
        features = {
            'apk_name': os.path.basename(apk_path),
            'package_name': a.get_package(),
            'min_sdk': a.get_min_sdk_version(), 
            'target_sdk': a.get_target_sdk_version(),
            'version_name': a.get_androidversion_name(),
            'version_code': a.get_androidversion_code(),
            'permissions': ','.join(a.get_permissions()),
            'activities_count': len(a.get_activities()),
            'services_count': len(a.get_services()),
            'receivers_count': len(a.get_receivers()),
            'certificate_issuer': cert_info,
            'api_calls_count': len(api_calls),
            'obfuscation_score': obf_score,
            'is_benign': 1 if 'Benign' in apk_path else 0  # 1 for benign, 0 for malicious
        }
        
        return features
    
    except Exception as e:
        print(f"Error analyzing {apk_path}: {str(e)}")
        return None

def get_processed_apks(csv_path):
    """Get list of already processed APK names from CSV"""
    processed = set()
    if os.path.exists(csv_path):
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            processed = {row['apk_name'] for row in reader}
    return processed

def process_and_save(apk_path, output_csv, processed_apks):
    """Process single APK and append results to CSV if not already processed"""
    apk_name = os.path.basename(apk_path)
    if apk_name in processed_apks:
        print(f"Skipping {apk_name} - already processed")
        return
        
    features = analyze_apk(apk_path)
    if features:
        with open(output_csv, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=features.keys())
            writer.writerow(features)
        print(f"Processed {apk_name}")
    else:
        print(f"Failed to process {apk_name}")

def main():
    benign_dir = "/home/john/MaliciousAPKDetection/Dataset/Benign/Benign"
    malicious_dir = "/home/john/MaliciousAPKDetection/Dataset/Malicious/Malicious"
    # Save output CSV in the new backup directory
    output_csv = "/home/john/MaliciousAPKDetection/Output/Try2/static_features.csv"
    
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
    # Get list of already processed APKs
    processed_apks = get_processed_apks(output_csv)
    
    # Initialize CSV with headers if it doesn't exist
    if not os.path.exists(output_csv):
        sample_apks = glob.glob(os.path.join(benign_dir, "*.apk"))
        if not sample_apks:
            print("No benign APKs found to initialize CSV.")
            return
        sample_features = analyze_apk(sample_apks[0])
        if sample_features:
            with open(output_csv, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=sample_features.keys())
                writer.writeheader()
    
    # Process benign APKs first
    benign_apks = glob.glob(os.path.join(benign_dir, "*.apk"))
    print(f"\nProcessing benign APKs...")
    with Pool() as pool:
        pool.starmap(process_and_save, [(apk, output_csv, processed_apks) for apk in benign_apks])
    
    # Then process malicious APKs
    malicious_apks = glob.glob(os.path.join(malicious_dir, "*.apk"))
    print(f"\nProcessing malicious APKs...")
    with Pool() as pool:
        pool.starmap(process_and_save, [(apk, output_csv, processed_apks) for apk in malicious_apks])
    
    print(f"\nAnalysis complete. Results saved to {output_csv}")

if __name__ == "__main__":
    main()
