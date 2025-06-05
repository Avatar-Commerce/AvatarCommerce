import requests
import os
import time
import tempfile
import base64
from typing import List, Dict, Optional

from langchain_openai import ChatOpenAI
from config import (
    OPENAI_API_KEY, 
    RAKUTEN_MERCHANT_ID, 
    RAKUTEN_TOKEN,
    HEYGEN_API_KEY,
    ELEVEN_LABS_API_KEY
)

from config import AFFILIATE_PLATFORMS, get_enabled_platforms, is_platform_enabled

class Chatbot:
    
    def get_product_recommendations(self, query: str, influencer_id: str) -> str:
        """Fetch product recommendations with fallback mechanism for available platforms."""
        # Sanitize and clean the query
        query = self.sanitize_query(query)
        
        try:
            # Get influencer's preferred platform (primary affiliate link)
            preferred_platform = self.get_influencer_preferred_platform(influencer_id)
            
            # Try preferred platform first if it's enabled
            if preferred_platform and is_platform_enabled(preferred_platform):
                products = self.fetch_platform_products(query, preferred_platform)
                if products:
                    return self.format_products(products, influencer_id, preferred_platform)
            
            # Try other enabled platforms in order
            enabled_platforms = get_enabled_platforms()
            for platform in enabled_platforms:
                if platform != preferred_platform:  # Skip if already tried
                    try:
                        products = self.fetch_platform_products(query, platform)
                        if products:
                            return self.format_products(products, influencer_id, platform)
                    except Exception as e:
                        print(f"Error with {platform}: {str(e)}")
                        continue
            
            # If no platforms worked, generate AI-based recommendations
            return self.generate_ai_product_recommendations(query, influencer_id)
        
        except Exception as e:
            print(f"Product recommendation error: {str(e)}")
            return self.generate_fallback_recommendations(query)

    def get_influencer_preferred_platform(self, influencer_id: str) -> str:
        """Get the influencer's preferred affiliate platform"""
        if not self.db:
            return None
            
        primary_affiliate = self.db.get_primary_affiliate_link(influencer_id)
        return primary_affiliate.get('platform') if primary_affiliate else None

    def fetch_platform_products(self, query: str, platform: str) -> List[Dict]:
        """Fetch products from a specific platform"""
        if platform == 'rakuten':
            return self.fetch_rakuten_products(query)
        elif platform == 'amazon':
            return self.fetch_amazon_products(query)
        elif platform == 'shareasale':
            return self.fetch_shareasale_products(query)
        elif platform == 'cj_affiliate':
            return self.fetch_cj_products(query)
        else:
            return []

    def fetch_rakuten_products(self, query: str) -> List[Dict]:
        """Fetch products from Rakuten API"""
        if not is_platform_enabled('rakuten'):
            return []
            
        config = AFFILIATE_PLATFORMS['rakuten']
        headers = {
            "Authorization": f"Bearer {config['credentials']['token']}",
            "Content-Type": "application/json"
        }
        
        params = {
            "keyword": query,
            "merchant_id": config['credentials']['merchant_id'],
            "hits": 5,
            "sort": "standard"
        }
        
        try:
            response = requests.get(
                config['base_url'], 
                headers=headers, 
                params=params, 
                timeout=10
            )
            
            if response.status_code == 200:
                products_data = response.json()
                products = products_data.get('items', [])
                return self.transform_products(products, 'rakuten')
        except Exception as e:
            print(f"Rakuten API error: {str(e)}")
        
        return []

    def fetch_amazon_products(self, query: str) -> List[Dict]:
        """Fetch products from Amazon Associates API (PAAPI 5.0)"""
        if not is_platform_enabled('amazon'):
            return []
        
        # Note: Amazon PAAPI 5.0 requires complex authentication
        # For now, return empty list - implement when you get Amazon credentials
        print("Amazon API not yet implemented - credentials needed")
        return []

    def fetch_shareasale_products(self, query: str) -> List[Dict]:
        """Fetch products from ShareASale API"""
        if not is_platform_enabled('shareasale'):
            return []
        
        # ShareASale API implementation
        print("ShareASale API not yet implemented - credentials needed")
        return []

    def fetch_cj_products(self, query: str) -> List[Dict]:
        """Fetch products from CJ Affiliate API"""
        if not is_platform_enabled('cj_affiliate'):
            return []
        
        # CJ Affiliate API implementation
        print("CJ Affiliate API not yet implemented - credentials needed")
        return []

    def generate_ai_product_recommendations(self, query: str, influencer_id: str) -> str:
        """Generate AI-based product recommendations when APIs aren't available"""
        prompt = f"""You are helping an influencer recommend products related to: {query}

        Generate 3-5 realistic, specific product recommendations that would be relevant.
        For each product, provide:
        - A specific product name
        - A realistic price range
        - A brief compelling description
        - Why it's relevant to the query

        Format as a clean, engaging product list that feels natural in a conversation.
        """
        
        try:
            response = self.llm.invoke(prompt)
            ai_response = response.content if hasattr(response, 'content') else str(response)
            
            # Get influencer's affiliate links for formatting
            affiliate_links = self.db.get_affiliate_links(influencer_id) if self.db else []
            
            # Add affiliate context if available
            if affiliate_links:
                primary_link = next((link for link in affiliate_links if link.get('is_primary')), affiliate_links[0])
                platform_name = primary_link.get('platform', '').replace('_', ' ').title()
                
                ai_response += f"\n\n💡 *I can help you find these products on {platform_name} - just let me know what interests you!*"
            else:
                ai_response += f"\n\n💡 *These are some great options to consider for {query}!*"
            
            return ai_response
            
        except Exception as e:
            print(f"AI recommendation error: {str(e)}")
            return self.generate_fallback_recommendations(query)

    def format_products(self, products: List[Dict], influencer_id: str, platform: str) -> str:
        """Format product recommendations with affiliate links"""
        if not products:
            return "Sorry, I couldn't find any products for that search."
        
        # Get influencer's affiliate ID for this platform
        affiliate_id = self.get_affiliate_id_for_platform(influencer_id, platform)
        
        formatted_products = []
        
        for product in products[:5]:  # Limit to 5 items
            title = product.get('productname', 'No title')
            price = product.get('price', 'Price not available')
            url = product.get('producturl', '#')
            image_url = product.get('imageurl', '')
            
            # Create affiliate URL based on platform
            affiliate_url = self.create_affiliate_url(url, platform, affiliate_id)
            
            product_info = f"🛒 **{title}** - {price}\n"
            if image_url:
                product_info += f"📷 [Product Image]({image_url})\n"
            product_info += f"🔗 [View Product]({affiliate_url})"
            
            formatted_products.append(product_info)

        if formatted_products:
            platform_name = AFFILIATE_PLATFORMS.get(platform, {}).get('name', platform.title())
            recommendations = "\n\n".join(formatted_products)
            return f"### Recommended Products from {platform_name}\n\n{recommendations}"
        else:
            return self.generate_ai_product_recommendations(query, influencer_id)

    def get_affiliate_id_for_platform(self, influencer_id: str, platform: str) -> str:
        """Get affiliate ID for a specific platform"""
        if not self.db:
            return ""
            
        affiliate_links = self.db.get_affiliate_links(influencer_id, platform)
        return affiliate_links[0].get('affiliate_id', '') if affiliate_links else ""

    def create_affiliate_url(self, base_url: str, platform: str, affiliate_id: str) -> str:
        """Create platform-specific affiliate URLs"""
        if not affiliate_id:
            return base_url
            
        if platform == 'rakuten':
            return f"{base_url}?mid={affiliate_id}"
        elif platform == 'amazon':
            return f"{base_url}?tag={affiliate_id}"
        elif platform == 'shareasale':
            return f"{base_url}?afftrack={affiliate_id}"
        elif platform == 'cj_affiliate':
            return f"{base_url}?cid={affiliate_id}"
        else:
            return f"{base_url}?ref={affiliate_id}"