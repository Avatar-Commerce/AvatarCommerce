import os
import requests
import json
import hashlib
import hmac
import base64
import time
from urllib.parse import urlencode, quote
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class AffiliateService:
    """Enhanced affiliate service supporting multiple platforms"""
    
    def __init__(self, db=None):
        self.db = db
        self.platforms = {
            'rakuten': RakutenAPI(),
            'amazon': AmazonAPI(),
            'shareasale': ShareASaleAPI(),
            'cj_affiliate': CJAffiliateAPI(),
            'skimlinks': SkimlinksAPI()
        }
    
    def search_products(self, query: str, platform: str, influencer_id: str, limit: int = 5) -> List[Dict]:
        """Search products across specified platform"""
        try:
            if platform not in self.platforms:
                logger.error(f"Unsupported platform: {platform}")
                return []
            
            # Get influencer's affiliate credentials
            affiliate_info = self.db.get_affiliate_link_by_platform(influencer_id, platform) if self.db else None
            
            if not affiliate_info:
                logger.warning(f"No affiliate credentials found for {platform}")
                return []
            
            # Search products using platform API
            api_instance = self.platforms[platform]
            products = api_instance.search_products(query, affiliate_info, limit)
            
            return products
            
        except Exception as e:
            logger.error(f"Error searching products on {platform}: {e}")
            return []
    
    def get_product_recommendations(self, query: str, influencer_id: str, limit: int = 3) -> Dict:
        """Get product recommendations from all available platforms"""
        try:
            all_products = []
            
            # Get influencer's connected platforms
            affiliate_links = self.db.get_affiliate_links(influencer_id) if self.db else []
            
            for link in affiliate_links:
                if link.get('is_active', True):
                    platform = link['platform']
                    products = self.search_products(query, platform, influencer_id, limit)
                    
                    for product in products:
                        product['platform'] = platform
                        product['platform_name'] = self.platforms[platform].get_platform_name()
                    
                    all_products.extend(products)
            
            # Sort by relevance and limit results
            sorted_products = sorted(all_products, key=lambda x: x.get('relevance_score', 0.5), reverse=True)
            
            return {
                'products': sorted_products[:limit],
                'total_found': len(all_products),
                'platforms_searched': len(affiliate_links)
            }
            
        except Exception as e:
            logger.error(f"Error getting product recommendations: {e}")
            return {'products': [], 'total_found': 0, 'platforms_searched': 0}


class RakutenAPI:
    """FIXED: Rakuten Advertising API implementation with correct credentials"""
    
    def __init__(self):
        # Updated base URL for Rakuten Advertising API
        self.base_url = "https://api.rakutenadvertising.com/productsearch/v1"
        
    def get_platform_name(self):
        return "Rakuten Advertising"
    
    def search_products(self, query: str, affiliate_info: Dict, limit: int = 5) -> List[Dict]:
        """Search products using Rakuten Product Search API with Client ID/Secret"""
        try:
            # FIXED: Use Client ID and Client Secret instead of merchant_id and token
            client_id = affiliate_info.get('client_id') or affiliate_info.get('rakuten_client_id')
            client_secret = affiliate_info.get('client_secret') or affiliate_info.get('rakuten_client_secret')
            application_id = affiliate_info.get('application_id') or affiliate_info.get('rakuten_application_id')
            
            if not client_id or not client_secret:
                logger.error("Missing Rakuten Client ID or Client Secret")
                return []
            
            # First get access token using Client Credentials flow
            access_token = self._get_access_token(client_id, client_secret)
            if not access_token:
                logger.error("Failed to get Rakuten access token")
                return []
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            params = {
                'keyword': query,
                'limit': min(limit, 20),  # Rakuten max is usually 20
                'format': 'json',
                'imageFlag': '1',  # Include images
                'sort': 'standard'  # Sort by relevance
            }
            
            # Add application ID if available
            if application_id:
                params['applicationId'] = application_id
            
            logger.info(f"Searching Rakuten for: {query}")
            
            response = requests.get(
                f"{self.base_url}/search",
                headers=headers,
                params=params,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                products = []
                
                # Parse Rakuten response format
                items = data.get('Items', []) or data.get('products', [])
                
                for item in items[:limit]:
                    # Handle different response formats
                    item_data = item.get('Item', item)
                    
                    product = {
                        'id': item_data.get('itemCode', '') or item_data.get('id', ''),
                        'name': item_data.get('itemName', '') or item_data.get('name', ''),
                        'price': self._parse_price(item_data.get('itemPrice', 0) or item_data.get('price', 0)),
                        'currency': 'USD',
                        'image_url': self._extract_image_url(item_data),
                        'affiliate_url': item_data.get('affiliateUrl', '') or item_data.get('url', ''),
                        'description': item_data.get('itemCaption', '') or item_data.get('description', ''),
                        'rating': float(item_data.get('reviewAverage', 0) or item_data.get('rating', 0)),
                        'review_count': int(item_data.get('reviewCount', 0) or item_data.get('review_count', 0)),
                        'availability': item_data.get('availability', 1) > 0,
                        'relevance_score': 0.8,
                        'shop_name': item_data.get('shopName', '') or item_data.get('shop', ''),
                        'shop_url': item_data.get('shopUrl', ''),
                        'category': item_data.get('genreId', '') or item_data.get('category', '')
                    }
                    
                    products.append(product)
                
                logger.info(f"Found {len(products)} products from Rakuten")
                return products
                
            else:
                logger.error(f"Rakuten API error: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"Rakuten search error: {e}")
            return []
    
    def _get_access_token(self, client_id: str, client_secret: str) -> Optional[str]:
        """Get OAuth access token using client credentials"""
        try:
            auth_url = "https://api.rakutenadvertising.com/auth/token"
            
            # Prepare authentication data
            auth_data = {
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': client_secret,
                'scope': 'productapi'
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            response = requests.post(
                auth_url,
                data=auth_data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                token_data = response.json()
                return token_data.get('access_token')
            else:
                logger.error(f"Rakuten auth error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Rakuten authentication error: {e}")
            return None
    
    def _extract_image_url(self, item_data):
        """Extract image URL from various possible formats"""
        # Try different possible image fields
        if 'mediumImageUrls' in item_data and item_data['mediumImageUrls']:
            return item_data['mediumImageUrls'][0].get('imageUrl', '')
        elif 'imageUrl' in item_data:
            return item_data['imageUrl']
        elif 'image_url' in item_data:
            return item_data['image_url']
        elif 'images' in item_data and item_data['images']:
            return item_data['images'][0] if isinstance(item_data['images'], list) else item_data['images']
        return ''
    
    def _parse_price(self, price_data):
        """Parse Rakuten price format"""
        if isinstance(price_data, (int, float)):
            return float(price_data)
        elif isinstance(price_data, str):
            # Remove currency symbols and parse
            import re
            price_str = re.sub(r'[^\d.]', '', price_data)
            try:
                return float(price_str)
            except ValueError:
                return 0.0
        elif isinstance(price_data, dict):
            # Handle price object format
            return float(price_data.get('amount', 0) or price_data.get('value', 0))
        return 0.0


class AmazonAPI:
    """Amazon Product Advertising API implementation"""
    
    def __init__(self):
        self.base_url = "https://webservices.amazon.com/paapi5/searchitems"
        
    def get_platform_name(self):
        return "Amazon Associates"
    
    def search_products(self, query: str, affiliate_info: Dict, limit: int = 5) -> List[Dict]:
        """Search products using Amazon PA-API 5.0"""
        try:
            access_key = affiliate_info.get('amazon_access_key')
            secret_key = affiliate_info.get('amazon_secret_key')
            partner_tag = affiliate_info.get('partner_tag')
            
            if not all([access_key, secret_key, partner_tag]):
                logger.error("Missing Amazon credentials")
                return []
            
            # Prepare Amazon PA-API request
            payload = {
                "Keywords": query,
                "Resources": [
                    "Images.Primary.Medium",
                    "ItemInfo.Title",
                    "ItemInfo.Features",
                    "Offers.Listings.Price",
                    "CustomerReviews.StarRating",
                    "CustomerReviews.Count"
                ],
                "PartnerTag": partner_tag,
                "PartnerType": "Associates",
                "Marketplace": "www.amazon.com",
                "ItemCount": min(limit, 10)  # Amazon max is 10
            }
            
            # Create AWS Signature Version 4
            headers = self._create_aws_headers(payload, access_key, secret_key)
            
            logger.info(f"Searching Amazon for: {query}")
            
            response = requests.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                products = []
                
                items = data.get('SearchResult', {}).get('Items', [])
                
                for item in items:
                    product = {
                        'id': item.get('ASIN', ''),
                        'name': item.get('ItemInfo', {}).get('Title', {}).get('DisplayValue', ''),
                        'price': self._extract_amazon_price(item),
                        'currency': 'USD',
                        'image_url': item.get('Images', {}).get('Primary', {}).get('Medium', {}).get('URL', ''),
                        'affiliate_url': item.get('DetailPageURL', ''),
                        'description': self._extract_features(item),
                        'rating': self._extract_rating(item),
                        'review_count': self._extract_review_count(item),
                        'availability': True,
                        'relevance_score': 0.9,
                        'shop_name': 'Amazon',
                        'category': ''
                    }
                    
                    products.append(product)
                
                logger.info(f"Found {len(products)} products from Amazon")
                return products
                
            else:
                logger.error(f"Amazon API error: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"Amazon search error: {e}")
            return []
    
    def _create_aws_headers(self, payload: Dict, access_key: str, secret_key: str) -> Dict:
        """Create AWS Signature Version 4 headers for Amazon PA-API"""
        import urllib.parse
        from datetime import datetime
        
        # AWS signature creation (simplified version)
        timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        date = timestamp[:8]
        
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'Host': 'webservices.amazon.com',
            'X-Amz-Date': timestamp,
            'X-Amz-Target': 'com.amazon.paapi5.v1.ProductAdvertisingAPIv1.SearchItems'
        }
        
        # For full implementation, you'd need proper AWS signature calculation
        # This is a simplified version - consider using boto3 or aws-requests-auth
        
        return headers
    
    def _extract_amazon_price(self, item):
        """Extract price from Amazon item data"""
        try:
            offers = item.get('Offers', {}).get('Listings', [])
            if offers:
                price_info = offers[0].get('Price', {})
                return float(price_info.get('Amount', 0)) / 100
            return 0.0
        except:
            return 0.0
    
    def _extract_features(self, item):
        """Extract product features as description"""
        try:
            features = item.get('ItemInfo', {}).get('Features', {}).get('DisplayValues', [])
            return ' '.join(features[:3])
        except:
            return ''
    
    def _extract_rating(self, item):
        """Extract customer rating"""
        try:
            return float(item.get('CustomerReviews', {}).get('StarRating', {}).get('Value', 0))
        except:
            return 0.0
    
    def _extract_review_count(self, item):
        """Extract review count"""
        try:
            return int(item.get('CustomerReviews', {}).get('Count', {}).get('Value', 0))
        except:
            return 0


class ShareASaleAPI:
    """ShareASale API implementation"""
    
    def __init__(self):
        self.base_url = "https://api.shareasale.com/w.cfm"
        
    def get_platform_name(self):
        return "ShareASale"
    
    def search_products(self, query: str, affiliate_info: Dict, limit: int = 5) -> List[Dict]:
        """Search products using ShareASale API"""
        try:
            api_token = affiliate_info.get('shareasale_api_token')
            secret_key = affiliate_info.get('shareasale_secret_key')
            affiliate_id = affiliate_info.get('affiliate_id')
            
            if not all([api_token, secret_key, affiliate_id]):
                logger.error("Missing ShareASale credentials")
                return []
            
            # ShareASale API parameters
            timestamp = str(int(time.time()))
            params = {
                'action': 'productSearch',
                'affiliateId': affiliate_id,
                'token': api_token,
                'timestamp': timestamp,
                'keyword': query,
                'limit': min(limit, 100),
                'format': 'json'
            }
            
            # Create signature
            sig_string = f"{timestamp}:{affiliate_id}:{api_token}"
            signature = hmac.new(
                secret_key.encode(),
                sig_string.encode(),
                hashlib.sha256
            ).hexdigest()
            
            params['signature'] = signature
            
            logger.info(f"Searching ShareASale for: {query}")
            
            response = requests.get(
                self.base_url,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                products = []
                
                if 'products' in data:
                    for item in data['products'][:limit]:
                        product = {
                            'id': str(item.get('productid', '')),
                            'name': item.get('name', ''),
                            'price': float(item.get('price', 0)),
                            'currency': 'USD',
                            'image_url': item.get('imageurl', ''),
                            'affiliate_url': item.get('affiliateurl', ''),
                            'description': item.get('description', ''),
                            'rating': 0,
                            'review_count': 0,
                            'availability': True,
                            'relevance_score': 0.7,
                            'shop_name': item.get('merchantname', ''),
                            'category': item.get('category', '')
                        }
                        
                        products.append(product)
                
                logger.info(f"Found {len(products)} products from ShareASale")
                return products
                
            else:
                logger.error(f"ShareASale API error: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"ShareASale search error: {e}")
            return []


class CJAffiliateAPI:
    """CJ Affiliate (Commission Junction) API implementation"""
    
    def __init__(self):
        self.base_url = "https://product-search.api.cj.com/v2/product-search"
        
    def get_platform_name(self):
        return "CJ Affiliate"
    
    def search_products(self, query: str, affiliate_info: Dict, limit: int = 5) -> List[Dict]:
        """Search products using CJ Affiliate API"""
        try:
            api_key = affiliate_info.get('cj_api_key')
            website_id = affiliate_info.get('website_id')
            
            if not api_key:
                logger.error("Missing CJ Affiliate API key")
                return []
            
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Accept': 'application/json'
            }
            
            params = {
                'keywords': query,
                'records-per-page': min(limit, 50),
                'page-number': 1,
                'sort-by': 'relevance',
                'currency': 'USD'
            }
            
            if website_id:
                params['website-id'] = website_id
            
            logger.info(f"Searching CJ Affiliate for: {query}")
            
            response = requests.get(
                self.base_url,
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                products = []
                
                items = data.get('products', [])
                
                for item in items:
                    product = {
                        'id': str(item.get('sku', '')),
                        'name': item.get('name', ''),
                        'price': float(item.get('price', 0)),
                        'currency': item.get('currency', 'USD'),
                        'image_url': item.get('imageUrl', ''),
                        'affiliate_url': item.get('clickUrl', ''),
                        'description': item.get('description', ''),
                        'rating': 0,
                        'review_count': 0,
                        'availability': item.get('inStock', True),
                        'relevance_score': 0.75,
                        'shop_name': item.get('advertiserName', ''),
                        'category': item.get('category', '')
                    }
                    
                    products.append(product)
                
                logger.info(f"Found {len(products)} products from CJ Affiliate")
                return products
                
            else:
                logger.error(f"CJ Affiliate API error: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"CJ Affiliate search error: {e}")
            return []


class SkimlinksAPI:
    """Skimlinks API implementation"""
    
    def __init__(self):
        self.base_url = "https://api-2.skimlinks.com"
        
    def get_platform_name(self):
        return "Skimlinks"
    
    def search_products(self, query: str, affiliate_info: Dict, limit: int = 5) -> List[Dict]:
        """Search products using Skimlinks Product Search API"""
        try:
            api_key = affiliate_info.get('skimlinks_api_key')
            publisher_id = affiliate_info.get('publisher_id')
            
            if not api_key:
                logger.error("Missing Skimlinks credentials")
                return []
            
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Accept': 'application/json'
            }
            
            params = {
                'query': query,
                'limit': min(limit, 20),
                'locale': 'US',
                'currency': 'USD'
            }
            
            logger.info(f"Searching Skimlinks for: {query}")
            
            response = requests.get(
                f"{self.base_url}/product/search",
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                products = []
                
                items = data.get('products', [])
                
                for item in items:
                    product = {
                        'id': str(item.get('id', '')),
                        'name': item.get('name', ''),
                        'price': float(item.get('price', {}).get('value', 0)),
                        'currency': item.get('price', {}).get('currency', 'USD'),
                        'image_url': item.get('image', ''),
                        'affiliate_url': item.get('url', ''),
                        'description': item.get('description', ''),
                        'rating': float(item.get('rating', 0)),
                        'review_count': int(item.get('reviewCount', 0)),
                        'availability': True,
                        'relevance_score': 0.7,
                        'shop_name': item.get('merchant', {}).get('name', ''),
                        'category': item.get('category', '')
                    }
                    
                    products.append(product)
                
                logger.info(f"Found {len(products)} products from Skimlinks")
                return products
                
            else:
                logger.error(f"Skimlinks API error: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"Skimlinks search error: {e}")
            return []


# Enhanced product recommendation formatter
class ProductRecommendationFormatter:
    """Format product recommendations for chat responses"""
    
    @staticmethod
    def format_recommendations(products: List[Dict], platform_info: Dict = None) -> str:
        """Format product recommendations for chat display"""
        if not products:
            return ""
        
        formatted = "\n\n🛍️ **Here are some great options I found:**\n\n"
        
        for i, product in enumerate(products[:3], 1):
            price_str = f"${product['price']:.2f}" if product['price'] > 0 else "Price varies"
            rating_str = f"⭐ {product['rating']:.1f}" if product['rating'] > 0 else ""
            
            formatted += f"**{i}. {product['name']}**\n"
            formatted += f"💰 {price_str}"
            
            if rating_str:
                formatted += f" | {rating_str}"
            
            if product.get('shop_name'):
                formatted += f" | 🏪 {product['shop_name']}"
            
            formatted += f"\n📝 {product['description'][:100]}...\n"
            
            if product.get('affiliate_url'):
                formatted += f"🔗 [View Product]({product['affiliate_url']})\n\n"
        
        if platform_info:
            platform_name = platform_info.get('platform_name', 'our partner')
            formatted += f"💡 *These recommendations are from {platform_name}. I earn a small commission if you make a purchase.*\n"
        
        return formatted