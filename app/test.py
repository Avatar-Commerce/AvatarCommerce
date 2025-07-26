# test_avatar_working.py - Test avatar creation with your 109 credits

import requests
import os
from dotenv import load_dotenv

load_dotenv()

HEYGEN_API_KEY = os.getenv("HEYGEN_API_KEY")
API_BASE_URL = "http://localhost:2000/api"

def test_with_existing_avatar():
    """Test using your existing avatar"""
    print("🧪 Testing with existing avatar...")
    
    # Your existing avatar ID from the logs
    existing_avatar_id = "0019574bacd74bd9a2cb76ac19bfb773"
    
    print(f"📋 Found existing avatar: {existing_avatar_id}")
    print("✅ This avatar should work for video generation!")
    
    return existing_avatar_id

def test_new_avatar_creation(image_path, token):
    """Test creating a new avatar with your 109 credits"""
    print(f"🎭 Testing new avatar creation with: {image_path}")
    
    if not os.path.exists(image_path):
        print(f"❌ Image not found: {image_path}")
        return None
    
    try:
        with open(image_path, 'rb') as f:
            files = {'file': f}
            
            response = requests.post(
                f"{API_BASE_URL}/avatar/create",
                headers={'Authorization': f'Bearer {token}'},
                files=files,
                timeout=120
            )
        
        print(f"📤 Response: {response.status_code}")
        
        if response.status_code == 201:
            data = response.json()
            if data.get('status') == 'success':
                avatar_id = data['data']['avatar_id']
                print(f"🎉 SUCCESS! New avatar created: {avatar_id}")
                return avatar_id
            else:
                print(f"❌ Error: {data.get('message')}")
        else:
            print(f"❌ HTTP Error: {response.status_code}")
            try:
                error_data = response.json()
                print(f"   Error details: {error_data}")
            except:
                print(f"   Response text: {response.text}")
        
        return None
        
    except Exception as e:
        print(f"❌ Exception: {str(e)}")
        return None

def main():
    print("🎯 Avatar Creation Test")
    print("=" * 40)
    
    # Test 1: Use existing avatar
    existing_avatar = test_with_existing_avatar()
    
    # Test 2: Create new avatar (if you want)
    print(f"\n🆕 Want to create a new avatar with your 109 credits?")
    token = input("Enter your auth token (or press Enter to skip): ").strip()
    
    if token:
        image_path = input("Enter path to image file: ").strip().strip('"')
        
        if image_path:
            new_avatar = test_new_avatar_creation(image_path, token)
            
            if new_avatar:
                print(f"\n🎉 Both avatars available:")
                print(f"   Existing: {existing_avatar}")
                print(f"   New: {new_avatar}")
        else:
            print("No image provided, skipping new avatar creation")
    else:
        print("No token provided, skipping new avatar creation")
    
    print(f"\n✅ You have working avatars ready for video generation!")

if __name__ == "__main__":
    main()