#!/usr/bin/env python3
"""
Test script to verify scan functionality
"""
import requests
import time
import json

BASE_URL = "http://localhost:5000"

def test_scan():
    print("Starting test scan...")

    # Start scan
    response = requests.post(f"{BASE_URL}/api/scan", json={"domain": "example.com"})
    if response.status_code != 200:
        print(f"Error starting scan: {response.text}")
        return

    scan_id = response.json()['scan_id']
    print(f"Scan started with ID: {scan_id}")

    # Poll for results
    max_attempts = 60
    for i in range(max_attempts):
        time.sleep(2)
        status_response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")

        if status_response.status_code != 200:
            print(f"Error getting status: {status_response.text}")
            return

        data = status_response.json()
        status = data.get('status')
        progress = data.get('progress', 0)

        print(f"Attempt {i+1}/{max_attempts} - Status: {status}, Progress: {progress}%")

        if status == 'completed':
            print("\n✅ Scan completed successfully!")
            print(f"\nResult keys: {list(data.get('result', {}).keys())}")

            # Check if result has the expected data
            result = data.get('result', {})
            if 'authenticity' in result:
                print(f"✓ Authenticity data present")
            if 'reconnaissance' in result:
                print(f"✓ Reconnaissance data present")
            if 'threat_analysis' in result:
                print(f"✓ Threat analysis data present")
            if 'graph_data' in result:
                print(f"✓ Graph data present")
            if 'web3_analysis' in result:
                print(f"✓ Web3 analysis data present")
            if 'workflow_results' in result:
                print(f"✓ Workflow results present")

            return True

        elif status == 'error':
            print(f"\n❌ Scan failed: {data.get('error')}")
            return False

    print("\n⏱️ Timeout waiting for scan to complete")
    return False

if __name__ == "__main__":
    test_scan()
