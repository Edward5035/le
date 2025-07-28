#!/usr/bin/env python3
"""
Simple test script for SalesStorm AI Flask application
"""
import requests
import time
import sys

def test_flask_app():
    """Test if the Flask app is running and responding"""
    base_url = "http://localhost:5000"
    
    # Wait a moment for the app to start
    time.sleep(2)
    
    try:
        # Test the main dashboard
        response = requests.get(base_url, timeout=5)
        if response.status_code == 200:
            print("✅ Dashboard (/) - OK")
            if "SalesStorm AI" in response.text:
                print("✅ Contains app name - OK")
            else:
                print("❌ Missing app name in response")
        else:
            print(f"❌ Dashboard returned status {response.status_code}")
            
        # Test API endpoint
        api_response = requests.get(f"{base_url}/api/dashboard", timeout=5)
        if api_response.status_code == 200:
            print("✅ API endpoint (/api/dashboard) - OK")
            data = api_response.json()
            if 'stats' in data:
                print("✅ API returns stats data - OK")
            else:
                print("❌ API missing stats data")
        else:
            print(f"❌ API returned status {api_response.status_code}")
            
        # Test other pages
        pages = ['/builder', '/activator', '/vault', '/promoter', '/niches']
        for page in pages:
            try:
                page_response = requests.get(f"{base_url}{page}", timeout=5)
                if page_response.status_code == 200:
                    print(f"✅ Page {page} - OK")
                else:
                    print(f"❌ Page {page} returned status {page_response.status_code}")
            except Exception as e:
                print(f"❌ Page {page} failed: {e}")
                
        print("\n🎉 SalesStorm AI is running successfully!")
        print(f"🌐 Open your browser to: {base_url}")
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to Flask app. Make sure it's running on localhost:5000")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
        
    return True

if __name__ == "__main__":
    print("🧪 Testing SalesStorm AI Flask Application...")
    print("=" * 50)
    
    success = test_flask_app()
    
    if success:
        print("\n🎯 All tests passed! The application is ready to use.")
    else:
        print("\n💥 Some tests failed. Check the error messages above.")
        sys.exit(1)