#!/bin/bash
APK_DIR="/home/john/MaliciousAPKDetection/Dataset/Benign/Benign"

for apk in "$APK_DIR"/*.apk; do
    adb install "$apk"
    echo "Installed: $apk"
done
