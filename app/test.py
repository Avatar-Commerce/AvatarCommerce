#!/usr/bin/env python3
"""
Debug script to check affiliate connections and product recommendations
Run this to diagnose issues with product recommendations
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the app directory to Python path
sys.path.append('./app')

try:
    from database import Database
    from chatbot import Chatbot, EnhancedChatbot
    from affiliate_service import AffiliateService
    from config import Config
    print("✅ All imports successful")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)

def debug_affiliate_connections():
    """Debug affiliate connections and product recommendations"""
    print("🔍 Starting affiliate connection debug...")
    
    # Initialize database
    try:
        db = Database()
        print("✅ Database connected")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return
    
    # Initialize chatbot
    try:
        chatbot = EnhancedChatbot(db=db)
        print("✅ EnhancedChatbot initialized")
    except Exception as e:
        print(f"❌ EnhancedChatbot failed, trying basic Chatbot: {e}")
        try:
            chatbot = Chatbot(db)
            print("⚠️ Using basic Chatbot")
        except Exception as e2:
            print(f"❌ All chatbot initialization failed: {e2}")
            return
    
    # Check if affiliate service is available
    if hasattr(chatbot, 'affiliate_service') and chatbot.affiliate_service:
        print("✅ Affiliate service is available")
        print(f"📋 Available platforms: {list(chatbot.affiliate_service.platforms.keys())}")
    else:
        print("❌ Affiliate service not available")
        print("   - Check if affiliate_service.py exists")
        print("   - Check if AffiliateService import is working")
        return
    
    # Test with a specific user
    print("\n🔍 Testing with user 'ademicho123'...")
    
    # Get user
    user = db.get_influencer_by_username('ademicho123')
    if not user:
        print("❌ User 'ademicho123' not found")
        return
    
    print(f"✅ Found user: {user['username']} (ID: {user['id']})")
    
    # Check affiliate links
    try:
        affiliate_links = db.get_affiliate_links(user['id'])
        print(f"📊 Affiliate links found: {len(affiliate_links)}")
        
        for link in affiliate_links:
            platform = link.get('platform', 'unknown')
            is_active = link.get('is_active', False)
            affiliate_id = link.get('affiliate_id', 'N/A')
            print(f"   - {platform}: {'✅ Active' if is_active else '❌ Inactive'} (ID: {affiliate_id})")
            
    except Exception as e:
        print(f"❌ Error getting affiliate links: {e}")
        return
    
    # Test product recommendation
    test_queries = ['recommend a laptop', 'suggest headphones', 'best phone']
    
    for query in test_queries:
        print(f"\n🛒 Testing query: '{query}'")
        
        try:
            # Test using affiliate service directly
            recommendations = chatbot.affiliate_service.get_product_recommendations(
                query=query,
                influencer_id=user['id'],
                limit=3
            )
            
            print(f"📦 Results: {recommendations['total_found']} products from {recommendations['platforms_searched']} platforms")
            
            if recommendations['products']:
                for i, product in enumerate(recommendations['products'][:2], 1):
                    print(f"   {i}. {product['name']} - ${product['price']:.2f} ({product.get('platform', 'unknown')})")
            else:
                print("   No products found")
                
        except Exception as e:
            print(f"❌ Product search failed: {e}")
    
    # Test comprehensive chat response
    print(f"\n💬 Testing comprehensive chat response...")
    
    try:
        if hasattr(chatbot, 'get_comprehensive_chat_response'):
            response = chatbot.get_comprehensive_chat_response(
                message="recommend a computer",
                influencer_id=user['id'],
                session_id="debug_session",
                influencer_name=user['username'],
                voice_mode=False,
                video_mode=False
            )
            
            print(f"✅ Comprehensive response generated:")
            print(f"   - Text length: {len(response['text'])} chars")
            print(f"   - Products included: {response.get('products_included', False)}")
            print(f"   - Knowledge enhanced: {response.get('knowledge_enhanced', False)}")
            print(f"   - Response preview: {response['text'][:100]}...")
            
        else:
            print("❌ get_comprehensive_chat_response method not available")
            
    except Exception as e:
        print(f"❌ Comprehensive chat test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_affiliate_connections()