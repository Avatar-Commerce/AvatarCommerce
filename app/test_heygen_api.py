# heygen_pro_debug.py - Debug script for HeyGen Pro API

import requests
import os
import json
import base64
from dotenv import load_dotenv

load_dotenv()

HEYGEN_API_KEY = os.getenv("HEYGEN_API_KEY")

def test_api_access():
    """Test basic API access and quota"""
    print("🔑 Testing HeyGen Pro API Access...")
    
    headers = {
        "X-Api-Key": HEYGEN_API_KEY,
        "Accept": "application/json"
    }
    
    # Test 1: Check remaining quota
    try:
        response = requests.get(
            "https://api.heygen.com/v1/user/remaining_quota",
            headers=headers,
            timeout=10
        )
        
        print(f"📊 Quota check: {response.status_code}")
        
        if response.status_code == 200:
            quota_data = response.json()
            print(f"✅ Remaining quota: {quota_data.get('data', {}).get('remaining_quota', 'unknown')}")
        else:
            print(f"❌ Quota check failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Quota check error: {str(e)}")
    
    # Test 2: Get avatar list
    try:
        response = requests.get(
            "https://api.heygen.com/v2/avatars",
            headers=headers,
            timeout=10
        )
        
        print(f"📋 Avatars list: {response.status_code}")
        
        if response.status_code == 200:
            avatars_data = response.json()
            avatar_count = len(avatars_data.get("data", {}).get("avatars", []))
            print(f"✅ Available avatars: {avatar_count}")
        else:
            print(f"❌ Avatars list failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Avatars list error: {str(e)}")

def test_photo_avatar_endpoints():
    """Test which photo avatar endpoints are available"""
    print(f"\n🎭 Testing Photo Avatar Endpoints...")
    
    headers = {
        "X-Api-Key": HEYGEN_API_KEY,
        "Accept": "application/json"
    }
    
    # Test different photo avatar endpoints
    endpoints = [
        "https://api.heygen.com/v2/photo_avatar",
        "https://api.heygen.com/v1/photo_avatar",
        "https://api.heygen.com/v2/photo_avatar/create",
        "https://api.heygen.com/v1/photo_avatar/create",
        "https://api.heygen.com/v2/photo_avatar/avatar_group",
        "https://api.heygen.com/v2/photo_avatar/avatar_group/create"
    ]
    
    for endpoint in endpoints:
        try:
            # Try GET first to see if endpoint exists
            response = requests.get(endpoint, headers=headers, timeout=5)
            print(f"📡 GET {endpoint}: {response.status_code}")
            
            if response.status_code not in [404, 405]:
                print(f"   Response: {response.text[:100]}...")
                
        except Exception as e:
            print(f"❌ {endpoint}: {str(e)}")

def test_asset_upload_detailed(image_path):
    """Detailed test of asset upload with different methods"""
    print(f"\n📁 Detailed Asset Upload Test: {image_path}")
    
    if not os.path.exists(image_path):
        print(f"❌ File not found: {image_path}")
        return
    
    with open(image_path, 'rb') as f:
        file_content = f.read()
    
    print(f"📊 File size: {len(file_content)} bytes")
    print(f"📊 File extension: {os.path.splitext(image_path)[1]}")
    
    # Method 1: Standard multipart upload
    print(f"\n🧪 Method 1: Standard multipart upload")
    try:
        headers = {
            "X-Api-Key": HEYGEN_API_KEY
        }
        
        files = {
            'file': (os.path.basename(image_path), file_content, 'image/jpeg')
        }
        
        response = requests.post(
            "https://upload.heygen.com/v1/asset",
            headers=headers,
            files=files,
            timeout=60
        )
        
        print(f"📤 Response: {response.status_code}")
        print(f"📄 Headers: {dict(response.headers)}")
        print(f"📄 Body: {response.text}")
        
        if response.status_code == 200:
            return response.json()
            
    except Exception as e:
        print(f"❌ Method 1 error: {str(e)}")
    
    # Method 2: Base64 upload (if supported)
    print(f"\n🧪 Method 2: Base64 upload")
    try:
        headers = {
            "X-Api-Key": HEYGEN_API_KEY,
            "Content-Type": "application/json"
        }
        
        file_b64 = base64.b64encode(file_content).decode('utf-8')
        
        payload = {
            "file_data": file_b64,
            "file_name": os.path.basename(image_path),
            "file_type": "image/jpeg"
        }
        
        response = requests.post(
            "https://upload.heygen.com/v1/asset",
            headers=headers,
            json=payload,
            timeout=60
        )
        
        print(f"📤 Response: {response.status_code}")
        print(f"📄 Body: {response.text}")
        
        if response.status_code == 200:
            return response.json()
            
    except Exception as e:
        print(f"❌ Method 2 error: {str(e)}")
    
    # Method 3: Try different upload endpoint
    print(f"\n🧪 Method 3: Alternative upload endpoint")
    try:
        headers = {
            "X-Api-Key": HEYGEN_API_KEY
        }
        
        files = {
            'file': (os.path.basename(image_path), file_content, 'image/jpeg')
        }
        
        response = requests.post(
            "https://api.heygen.com/v1/asset/upload",
            headers=headers,
            files=files,
            timeout=60
        )
        
        print(f"📤 Response: {response.status_code}")
        print(f"📄 Body: {response.text}")
        
        if response.status_code == 200:
            return response.json()
            
    except Exception as e:
        print(f"❌ Method 3 error: {str(e)}")
    
    return None

def test_avatar_creation_methods(image_path):
    """Test different avatar creation methods"""
    print(f"\n🎭 Testing Avatar Creation Methods...")
    
    if not os.path.exists(image_path):
        print(f"❌ File not found: {image_path}")
        return
    
    with open(image_path, 'rb') as f:
        file_content = f.read()
    
    import time
    avatar_name = f"test_avatar_{int(time.time())}"
    
    # Method 1: Direct photo avatar creation with multipart
    print(f"\n🧪 Method 1: Direct photo avatar creation")
    try:
        headers = {
            "X-Api-Key": HEYGEN_API_KEY
        }
        
        files = {
            'image': (os.path.basename(image_path), file_content, 'image/jpeg')
        }
        
        data = {
            'name': avatar_name
        }
        
        response = requests.post(
            "https://api.heygen.com/v2/photo_avatar/create",
            headers=headers,
            files=files,
            data=data,
            timeout=120
        )
        
        print(f"📤 Response: {response.status_code}")
        print(f"📄 Body: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            if not result.get("error"):
                avatar_id = result.get("data", {}).get("id")
                print(f"✅ SUCCESS! Avatar created: {avatar_id}")
                return avatar_id
                
    except Exception as e:
        print(f"❌ Method 1 error: {str(e)}")
    
    # Method 2: Try with different field name
    print(f"\n🧪 Method 2: Different field name")
    try:
        headers = {
            "X-Api-Key": HEYGEN_API_KEY
        }
        
        files = {
            'file': (os.path.basename(image_path), file_content, 'image/jpeg')
        }
        
        data = {
            'name': avatar_name + "_v2"
        }
        
        response = requests.post(
            "https://api.heygen.com/v2/photo_avatar/create",
            headers=headers,
            files=files,
            data=data,
            timeout=120
        )
        
        print(f"📤 Response: {response.status_code}")
        print(f"📄 Body: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            if not result.get("error"):
                avatar_id = result.get("data", {}).get("id")
                print(f"✅ SUCCESS! Avatar created: {avatar_id}")
                return avatar_id
                
    except Exception as e:
        print(f"❌ Method 2 error: {str(e)}")
    
    return None

def check_api_documentation():
    """Check API documentation and available endpoints"""
    print(f"\n📚 Checking API Capabilities...")
    
    headers = {
        "X-Api-Key": HEYGEN_API_KEY,
        "Accept": "application/json"
    }
    
    # Check user info
    try:
        response = requests.get(
            "https://api.heygen.com/v1/user/info",
            headers=headers,
            timeout=10
        )
        
        print(f"👤 User info: {response.status_code}")
        if response.status_code == 200:
            user_data = response.json()
            print(f"📄 User data: {json.dumps(user_data, indent=2)}")
        else:
            print(f"📄 Response: {response.text}")
            
    except Exception as e:
        print(f"❌ User info error: {str(e)}")

if __name__ == "__main__":
    print("🔧 HeyGen Pro API Debug")
    print("=" * 50)
    
    if not HEYGEN_API_KEY:
        print("❌ HEYGEN_API_KEY not found")
        exit(1)
    
    # Test 1: Basic API access
    test_api_access()
    
    # Test 2: Check available endpoints
    test_photo_avatar_endpoints()
    
    # Test 3: Check API documentation
    check_api_documentation()
    
    # Test 4: File upload and avatar creation
    print("\n" + "=" * 50)
    image_path = input("Enter path to test image (or press Enter to skip): ").strip().strip('"')
    
    if image_path and os.path.exists(image_path):
        # Test asset upload
        asset_result = test_asset_upload_detailed(image_path)
        
        # Test avatar creation
        avatar_id = test_avatar_creation_methods(image_path)
        
        if avatar_id:
            print(f"\n🎉 SUCCESS! Avatar created with ID: {avatar_id}")
        else:
            print(f"\n❌ All avatar creation methods failed")
    else:
        print("Skipping file tests")
    
    print("\n🎉 Debug complete!")
    print("\nNext steps:")
    print("1. Check if any method worked above")
    print("2. If quota is 0, wait for renewal or upgrade")
    print("3. If methods failed, the API might have changed - contact HeyGen support")
    print("4. Try smaller image files (under 2MB)")
    print("5. Ensure image clearly shows a single face")