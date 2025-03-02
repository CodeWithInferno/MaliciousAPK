# # import os
# # import time
# # import subprocess
# # import pandas as pd
# # import re
# # import random
# # from scapy.all import rdpcap

# # # Define the APK directory where APKs are stored
# # APK_DIR = "/home/john/MaliciousAPKDetection/Dataset/Benign/Benign"  # CHANGE THIS TO YOUR ACTUAL DIRECTORY
# # OUTPUT_CSV = "/home/john/MaliciousAPKDetection/Output/Dynamic/malware_data.csv"

# # # Define features to collect
# # data = []

# # # Function to extract permissions
# # def get_permissions(package_name):
# #     try:
# #         output = subprocess.check_output(f"adb shell dumpsys package {package_name} | grep permission", shell=True).decode()
# #         return list(set(re.findall(r'android.permission.[A-Z_]+', output)))
# #     except:
# #         return []

# # # Function to extract API calls
# # suspicious_calls = ["DexClassLoader", "exec", "getRunningTasks", "HttpURLConnection"]
# # def get_api_calls():
# #     api_usage = {call: 0 for call in suspicious_calls}
# #     try:
# #         output = subprocess.check_output("adb logcat -d -s AndroidRuntime", shell=True).decode()
# #         for call in suspicious_calls:
# #             api_usage[call] = output.count(call)
# #     except:
# #         pass
# #     return api_usage

# # # Function to extract network activity
# # def get_network_activity():
# #     try:
# #         subprocess.run("adb shell tcpdump -i any -w /sdcard/network.pcap", shell=True, timeout=10)
# #         subprocess.run("adb pull /sdcard/network.pcap", shell=True)
# #         packets = rdpcap("network.pcap")
# #         ips = list(set(pkt["IP"].dst for pkt in packets if pkt.haslayer("IP")))
# #         return ips
# #     except:
# #         return []

# # # Function to extract file system changes
# # def get_file_modifications():
# #     try:
# #         output = subprocess.check_output("adb shell ls -alR /sdcard/", shell=True).decode()
# #         hidden_files = re.findall(r'\.(?!nomedia)[^\s]+', output)
# #         return hidden_files
# #     except:
# #         return []

# # # Function to extract CPU usage
# # def get_cpu_usage(package_name):
# #     try:
# #         output = subprocess.check_output("adb shell top -n 1 -m 10", shell=True).decode()
# #         for line in output.split("\n"):
# #             if package_name in line:
# #                 return float(re.findall(r"\d+\.\d+", line)[0])
# #     except:
# #         pass
# #     return 0

# # # Function to simulate random user interaction
# # def random_interaction():
# #     for _ in range(10):
# #         x1, y1 = random.randint(100, 800), random.randint(200, 1200)
# #         x2, y2 = random.randint(100, 800), random.randint(200, 1200)
# #         subprocess.run(f"adb shell input tap {x1} {y1}", shell=True)
# #         subprocess.run(f"adb shell input swipe {x1} {y1} {x2} {y2}", shell=True)
# #         time.sleep(random.randint(1, 3))

# # # Loop through APKs
# # for apk in os.listdir(APK_DIR):
# #     if apk.endswith(".apk"):
# #         apk_path = os.path.join(APK_DIR, apk)
# #         print(f"Installing {apk}...")
# #         install_result = subprocess.run(f"adb install {apk_path}", shell=True, capture_output=True).stdout.decode()
        
# #         if "Success" in install_result:
# #             # Get package name
# #             package_name = subprocess.check_output("adb shell pm list packages -3", shell=True).decode().split("\n")[-2].split(":")[-1]
            
# #             print(f"Running {package_name}...")
# #             subprocess.run(f"adb shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1", shell=True)
# #             time.sleep(5)
            
# #             # Perform random interactions
# #             random_interaction()
            
# #             # Extract features
# #             permissions = get_permissions(package_name)
# #             api_calls = get_api_calls()
# #             network_requests = get_network_activity()
# #             file_mods = get_file_modifications()
# #             cpu_usage = get_cpu_usage(package_name)
            
# #             # Save data
# #             data.append([apk, permissions, api_calls, network_requests, file_mods, cpu_usage, "malicious"])
            
# #             # Write output to CSV after each app
# #             columns = ["APK Name", "Permissions Used", "API Calls", "Network Requests", "Hidden Files", "CPU Usage", "Malware (Label)"]
# #             df = pd.DataFrame(data, columns=columns)
# #             df.to_csv(OUTPUT_CSV, index=False)
# #             print(f"Data for {apk} saved to CSV.")
            
# #             # Uninstall the app
# #             subprocess.run(f"adb uninstall {package_name}", shell=True)
# #         else:
# #             print(f"Failed to install {apk}. Skipping...")

# # print("Data collection complete. CSV saved as", OUTPUT_CSV)














import os
import time
import subprocess
import pandas as pd
import re
import random

# Define the APK directory where APKs are stored
APK_DIR = "/home/john/MaliciousAPKDetection/Dataset/Benign/Benign"  # CHANGE THIS TO YOUR ACTUAL DIRECTORY
OUTPUT_CSV = "/home/john/MaliciousAPKDetection/Output/Dynamic/malware_data.csv"

# Set malware label: 0 for benign, 1 for malicious
MALWARE_LABEL = 1

# Define features to collect
data = []

# Function to extract permissions
def get_permissions(package_name):
    try:
        output = subprocess.check_output(f"adb shell dumpsys package {package_name} | grep permission", shell=True).decode()
        permissions = list(set(re.findall(r'android.permission.[A-Z_]+', output)))
        dangerous_perms = ["SEND_SMS", "READ_SMS", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_CONTACTS", "WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE", "CAMERA"]
        dangerous_used = [perm for perm in permissions if any(dp in perm for dp in dangerous_perms)]
        return {"total": len(permissions), "permissions_used": permissions, "dangerous": dangerous_used}
    except:
        return {"total": 0, "permissions_used": [], "dangerous": []}

# Function to extract API calls
extended_suspicious_calls = ["DexClassLoader", "exec", "getRunningTasks", "HttpURLConnection",
                             "getDeviceId", "sendTextMessage", "getSubscriberId", "getInstalledPackages",
                             "getLastKnownLocation", "getActiveNetworkInfo", "getAccounts",
                             "setWifiEnabled", "Socket", "ProcessBuilder", "Runtime.getRuntime().exec"]
def get_extended_api_calls():
    api_usage = {call: 0 for call in extended_suspicious_calls}
    try:
        output = subprocess.check_output("adb logcat -d", shell=True).decode()
        for call in extended_suspicious_calls:
            api_usage[call] = output.count(call)
    except:
        pass
    return api_usage

# Function to analyze logcat for suspicious keywords
def logcat_analysis():
    try:
        output = subprocess.check_output("adb logcat -d", shell=True).decode()
        suspicious_keywords = ["hack", "root", "exploit", "token", "credential", "bypass", "error", "exception"]
        found = [word for word in suspicious_keywords if word in output.lower()]
        return found
    except:
        return []

# Function to get battery usage
def get_battery_usage():
    try:
        output = subprocess.check_output("adb shell dumpsys battery", shell=True).decode()
        battery_level = int(re.findall(r'level: (\d+)', output)[0])
        return battery_level
    except:
        return -1

# Function to measure CPU usage over time
def get_cpu_usage(package_name):
    try:
        output = subprocess.check_output("adb shell top -n 1 -m 10", shell=True).decode()
        for line in output.split("\n"):
            if package_name in line:
                return float(re.findall(r"\d+\.\d+", line)[0])
    except:
        pass
    return 0

def measure_cpu_over_time(package_name, samples=5):
    usages = []
    for _ in range(samples):
        usages.append(get_cpu_usage(package_name))
        time.sleep(2)
    return max(usages)

# Function to simulate random user interaction
def random_interaction():
    for _ in range(10):
        x1, y1 = random.randint(100, 800), random.randint(200, 1200)
        x2, y2 = random.randint(100, 800), random.randint(200, 1200)
        subprocess.run(f"adb shell input tap {x1} {y1}", shell=True)
        subprocess.run(f"adb shell input swipe {x1} {y1} {x2} {y2}", shell=True)
        time.sleep(random.randint(1, 3))

# Loop through APKs
for apk in os.listdir(APK_DIR):
    if apk.endswith(".apk"):
        apk_path = os.path.join(APK_DIR, apk)
        print(f"Installing {apk}...")
        install_result = subprocess.run(f"adb install {apk_path}", shell=True, capture_output=True).stdout.decode()
        
        if "Success" in install_result:
            package_name = subprocess.check_output("adb shell pm list packages -3", shell=True).decode().split("\n")[-2].split(":")[-1]
            print(f"Running {package_name}...")
            subprocess.run(f"adb shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1", shell=True)
            time.sleep(5)

            random_interaction()
            
            permissions = get_permissions(package_name)
            api_calls = get_extended_api_calls()
            logs = logcat_analysis()
            battery_before = get_battery_usage()
            cpu_usage = measure_cpu_over_time(package_name)
            battery_after = get_battery_usage()
            battery_drain = battery_before - battery_after if battery_before != -1 and battery_after != -1 else None
            
            # Enhanced data save
            data.append([
                apk,
                permissions,
                api_calls,
                logs,
                battery_drain,
                cpu_usage,
                MALWARE_LABEL
            ])
            
            # Write output to CSV
            columns = ["APK Name", "Permissions Analysis", "API Calls", "Suspicious Logs", "Battery Drain", "CPU Usage", "Malware (Label)"]
            df = pd.DataFrame(data, columns=columns)
            df.to_csv(OUTPUT_CSV, index=False)
            print(f"Data for {apk} saved to CSV.")
            
            subprocess.run(f"adb uninstall {package_name}", shell=True)
        else:
            print(f"Failed to install {apk}. Skipping...")

print("Data collection complete. CSV saved as", OUTPUT_CSV)














