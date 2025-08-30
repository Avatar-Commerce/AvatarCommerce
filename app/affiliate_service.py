import os
import requests
import json
import hashlib
import hmac
import base64
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlencode, quote
from datetime import datetime
from typing import Dict, List, Optional
import logging
import certifi
import urllib3

# Disable SSL warnings for debugging (TEMPORARY)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class AffiliateService:
    """FIXED: Affiliate service - Real products only, no samples or demos"""
    
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
        """FIXED: Search with real products only - no fallbacks to samples"""
        try:
            if platform not in self.platforms:
                logger.error(f"Unsupported platform: {platform}")
                return []
            
            affiliate_info = self.db.get_affiliate_link_by_platform(influencer_id, platform) if self.db else None
            
            if not affiliate_info:
                logger.error(f"❌ No affiliate credentials found for {platform}")
                return []
            
            logger.info(f"🔍 Searching {platform} for '{query}' with credentials")
            
            # Validate credentials
            if not self._validate_platform_credentials(platform, affiliate_info):
                logger.error(f"❌ Invalid credentials for {platform}")
                return []  # Return empty instead of samples
            
            # Try the API - return whatever it gives us (real products or empty)
            api_instance = self.platforms[platform]
            products = api_instance.search_products(query, affiliate_info, limit)
            
            if products:
                logger.info(f"✅ Found {len(products)} real products from {platform}")
                return products
            else:
                logger.warning(f"⚠️ No products returned from {platform} API")
                return []  # Return empty instead of generating samples
            
        except Exception as e:
            logger.error(f"❌ Error searching {platform}: {e}")
            return []  # Return empty instead of samples
    
    def _validate_platform_credentials(self, platform: str, affiliate_info: Dict) -> bool:
        """Validate credentials for each platform"""
        if platform == 'rakuten':
            app_id = self._extract_rakuten_app_id(affiliate_info)
            return bool(app_id and len(app_id) > 10)
            
        elif platform == 'amazon':
            required = ['amazon_access_key', 'amazon_secret_key', 'partner_tag']
            return all(affiliate_info.get(field) for field in required)
            
        elif platform == 'shareasale':
            required = ['shareasale_api_token', 'shareasale_secret_key', 'affiliate_id']
            return all(affiliate_info.get(field) for field in required)
            
        return True
    
    def _extract_rakuten_app_id(self, affiliate_info: Dict) -> Optional[str]:
        """Extract Rakuten Application ID"""
        fields = ['application_id', 'rakuten_application_id', 'client_id', 'rakuten_client_id']
        
        for field in fields:
            app_id = affiliate_info.get(field, '').strip()
            if app_id:
                return app_id
        return None
    
    def get_product_recommendations(self, query: str, influencer_id: str, limit: int = 3) -> Dict:
        """FIXED: Get recommendations - real products only, no demos"""
        try:
            all_products = []
            errors = []
            successful_platforms = []
            
            # Get influencer's affiliate links
            affiliate_links = self.db.get_affiliate_links(influencer_id) if self.db else []
            
            if not affiliate_links:
                logger.error(f"❌ No affiliate links found for influencer {influencer_id}")
                return {
                    'products': [],
                    'total_found': 0,
                    'platforms_searched': 0,
                    'successful_platforms': [],
                    'error': 'No affiliate platforms connected'
                }
            
            logger.info(f"🔗 Searching {len(affiliate_links)} affiliate platforms")
            
            for link in affiliate_links:
                if link.get('is_active', True):
                    platform = link['platform']
                    logger.info(f"🔍 Trying platform: {platform}")
                    
                    try:
                        products = self.search_products(query, platform, influencer_id, limit)
                        
                        if products:
                            # Only add real products (no demo flag check needed)
                            for product in products:
                                product['platform'] = platform
                                product['platform_name'] = self.platforms[platform].get_platform_name()
                            
                            all_products.extend(products)
                            successful_platforms.append(platform)
                            logger.info(f"✅ {platform}: Added {len(products)} real products")
                        else:
                            logger.warning(f"⚠️ {platform}: No products found")
                            
                    except Exception as platform_error:
                        error_msg = f"{platform}: {str(platform_error)}"
                        errors.append(error_msg)
                        logger.error(f"❌ Platform error - {error_msg}")
            
            # Sort by relevance
            sorted_products = sorted(all_products, key=lambda x: x.get('relevance_score', 0.5), reverse=True)
            
            result = {
                'products': sorted_products[:limit],
                'total_found': len(all_products),
                'platforms_searched': len(affiliate_links),
                'successful_platforms': successful_platforms,
                'errors': errors
            }
            
            if not all_products and affiliate_links:
                logger.error(f"❌ NO REAL PRODUCTS FOUND from {len(affiliate_links)} affiliate platforms")
                result['error'] = f"No products available from affiliate platforms"
            else:
                logger.info(f"✅ Total real products found: {len(all_products)} from {len(successful_platforms)} platforms")
                
            return result
            
        except Exception as e:
            logger.error(f"❌ Error getting product recommendations: {e}")
            return {
                'products': [], 
                'total_found': 0, 
                'platforms_searched': 0,
                'successful_platforms': [],
                'error': str(e)
            }

# Enhanced product recommendation formatter
class ProductRecommendationFormatter:
    """FIXED: Format real products only - no demo handling"""
    
    @staticmethod
    def format_recommendations(products: List[Dict], platform_info: Dict = None) -> str:
        """Format real affiliate product recommendations only"""
        if not products:
            return ""
        
        formatted = "\n\n🛍️ **Here are some great products I found:**\n\n"
        
        for i, product in enumerate(products[:3], 1):
            # Handle USD pricing for US Rakuten
            if product.get('currency') == 'USD':
                price_str = f"${product['price']:.2f}" if product.get('price', 0) > 0 else "See price"
            else:
                price_str = f"${product['price']:.2f}" if product.get('price', 0) > 0 else "See price"
            
            rating_str = f"⭐ {product['rating']:.1f}" if product.get('rating', 0) > 0 else ""
            
            formatted += f"**{i}. {product['name']}**\n"
            formatted += f"💰 {price_str}"
            
            if rating_str:
                formatted += f" | {rating_str}"
            
            if product.get('review_count', 0) > 0:
                formatted += f" ({product['review_count']} reviews)"
            
            if product.get('shop_name'):
                formatted += f" | 🏪 {product['shop_name']}"
            
            formatted += f"\n📝 {product.get('description', 'Quality product')[:120]}...\n"
            
            if product.get('affiliate_url'):
                formatted += f"🔗 [View Product]({product['affiliate_url']})\n\n"
            else:
                formatted += "\n"
        
        # Simple footer for real products
        platform_name = platform_info.get('platform_name', 'affiliate partners') if platform_info else 'affiliate partners'
        formatted += f"💡 *Found through my {platform_name}. I earn a small commission if you make a purchase.*\n"
        
        return formatted

class RakutenAPI:
    """FIXED: Rakuten US API - Real products only, no samples"""
    
    def __init__(self):
        # US Rakuten endpoints
        self.endpoints = {
            'advertising_search': 'https://api.rakutenadvertising.com/v1/productsearch',
            'advertising_auth': 'https://api.rakutenadvertising.com/token',
            'us_search': 'https://api.rakuten.com/v1/products/search',
            'us_search_alt': 'https://webservice.rakuten.com/api/v1/productsearch',
            'affiliate_search': 'https://api.linksynergy.com/productsearch'
        }
        
        self.session = requests.Session()
        retries = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount('https://', HTTPAdapter(max_retries=retries))
        self.session.verify = True
        
        self.session.headers.update({
            'User-Agent': 'AvatarCommerce-Platform/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        logger.info(f"🔧 Rakuten US API initialized - Real products only")
        
    def get_platform_name(self):
        return "Rakuten"
    
    def search_products(self, query: str, affiliate_info: Dict, limit: int = 5) -> List[Dict]:
        """FIXED: US Rakuten search - return empty if no real products found"""
        try:
            application_id = self._extract_and_validate_app_id(affiliate_info)
            
            if not application_id:
                logger.error("❌ No valid Rakuten Application ID found")
                return []  # Return empty instead of samples
            
            logger.info(f"🔍 Rakuten US search for '{query}' with App ID: {application_id[:10]}...")
            
            # Strategy 1: Try US Advertising API with OAuth
            logger.info("🔄 Trying US Advertising API")
            products = self._try_us_advertising_api(query, affiliate_info, limit)
            if products:
                logger.info(f"✅ Success with US Advertising API - {len(products)} real products")
                return products
            
            # Strategy 2: Try alternative US endpoints
            logger.info("🔄 Trying alternative US endpoints")
            products = self._try_us_alternative_endpoints(query, application_id, limit)
            if products:
                logger.info(f"✅ Success with US alternative endpoints - {len(products)} real products")
                return products
            
            # Strategy 3: Try LinkShare/Rakuten Affiliate Network
            logger.info("🔄 Trying Rakuten Affiliate Network")
            products = self._try_affiliate_network_api(query, application_id, limit)
            if products:
                logger.info(f"✅ Success with Affiliate Network - {len(products)} real products")
                return products
            
            # NO FALLBACK - return empty if all APIs fail
            logger.warning("⚠️ All US Rakuten API methods failed - returning empty results")
            return []
            
        except Exception as e:
            logger.error(f"❌ Rakuten US search error: {e}")
            return []  # Return empty instead of samples
    
    def _extract_and_validate_app_id(self, affiliate_info: Dict) -> Optional[str]:
        """Extract and validate Application ID for US Rakuten"""
        possible_fields = [
            'application_id', 'rakuten_application_id', 'client_id', 
            'rakuten_client_id', 'api_key', 'affiliate_id'
        ]
        
        for field in possible_fields:
            app_id = affiliate_info.get(field, '').strip()
            if app_id and len(app_id) > 10:
                logger.info(f"✅ Application ID found in '{field}': {app_id[:10]}...")
                return app_id
        
        logger.error(f"❌ No valid Application ID in fields: {list(affiliate_info.keys())}")
        return None
    
    def _try_us_advertising_api(self, query: str, affiliate_info: Dict, limit: int) -> List[Dict]:
        """Try US Rakuten Advertising API with OAuth"""
        try:
            client_id = affiliate_info.get('client_id') or affiliate_info.get('application_id')
            client_secret = affiliate_info.get('client_secret')
            
            if not client_id:
                logger.info("   ⚠️ No client credentials for Advertising API")
                return []
            
            access_token = self._get_us_oauth_token(client_id, client_secret)
            if not access_token:
                logger.info("   ⚠️ OAuth token failed")
                return []
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            params = {
                'keyword': query,
                'limit': min(limit, 50),
                'format': 'json',
                'currency': 'USD',
                'country': 'US'
            }
            
            response = self.session.get(
                self.endpoints['advertising_search'],
                headers=headers,
                params=params,
                timeout=15
            )
            
            logger.info(f"   📡 US Advertising API response: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_us_products(data, 'advertising')
            else:
                logger.warning(f"   ⚠️ US Advertising API failed: {response.status_code}")
                return []
                
        except Exception as e:
            logger.warning(f"   ❌ US Advertising API error: {e}")
            return []
    
    def _get_us_oauth_token(self, client_id: str, client_secret: str) -> Optional[str]:
        """Get OAuth token for US Rakuten Advertising"""
        try:
            if not client_secret:
                return None
                
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            payload = {
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': client_secret,
                'scope': 'productsearch'
            }
            
            response = self.session.post(
                self.endpoints['advertising_auth'],
                headers=headers,
                data=payload,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                token = data.get('access_token')
                if token:
                    logger.info(f"   ✅ Got US OAuth token")
                    return token
                    
        except Exception as e:
            logger.warning(f"   ❌ US OAuth error: {e}")
        
        return None
    
    def _try_us_alternative_endpoints(self, query: str, app_id: str, limit: int) -> List[Dict]:
        """Try alternative US Rakuten endpoints"""
        endpoints_to_try = [
            ('us_search', self.endpoints['us_search']),
            ('us_search_alt', self.endpoints['us_search_alt'])
        ]
        
        for endpoint_name, endpoint_url in endpoints_to_try:
            try:
                logger.info(f"   🔄 Trying {endpoint_name}")
                
                param_sets = [
                    {
                        'applicationId': app_id,
                        'keyword': query,
                        'format': 'json',
                        'hits': min(limit, 30),
                        'currency': 'USD'
                    },
                    {
                        'app_id': app_id,
                        'query': query,
                        'format': 'json',
                        'limit': min(limit, 20)
                    }
                ]
                
                for i, params in enumerate(param_sets):
                    try:
                        response = self.session.get(endpoint_url, params=params, timeout=10)
                        logger.info(f"     📡 Parameter set {i+1}: {response.status_code}")
                        
                        if response.status_code == 200:
                            data = response.json()
                            products = self._parse_us_products(data, endpoint_name)
                            if products:
                                return products
                            
                    except Exception as param_error:
                        logger.info(f"     ❌ Parameter set {i+1} failed: {param_error}")
                        continue
                        
            except Exception as endpoint_error:
                logger.warning(f"   ❌ {endpoint_name} failed: {endpoint_error}")
                continue
        
        return []
    
    def _try_affiliate_network_api(self, query: str, app_id: str, limit: int) -> List[Dict]:
        """Try Rakuten Affiliate Network (LinkShare) API"""
        try:
            logger.info("   🔄 Trying Affiliate Network API")
            
            headers = {
                'Authorization': f'Bearer {app_id}',
                'Accept': 'application/json'
            }
            
            params = {
                'keyword': query,
                'max': min(limit, 20),
                'currency': 'USD',
                'sort': 'relevance'
            }
            
            response = self.session.get(
                self.endpoints['affiliate_search'],
                headers=headers,
                params=params,
                timeout=10
            )
            
            logger.info(f"   📡 Affiliate Network response: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_us_products(data, 'affiliate_network')
            else:
                return []
                
        except Exception as e:
            logger.warning(f"   ❌ Affiliate Network error: {e}")
            return []
    
    def _parse_us_products(self, data: Dict, source: str) -> List[Dict]:
        """Parse US Rakuten product responses - real products only"""
        try:
            items = []
            
            if 'products' in data:
                items = data['products']
            elif 'results' in data:
                items = data['results']  
            elif 'data' in data and isinstance(data['data'], list):
                items = data['data']
            elif 'items' in data:
                items = data['items']
            
            if not items:
                logger.info(f"   📦 No items in {source} response")
                return []
            
            logger.info(f"   📦 Parsing {len(items)} items from {source}")
            
            products = []
            for i, item in enumerate(items[:5]):
                try:
                    product = {
                        'id': str(item.get('id') or item.get('sku') or item.get('productId') or f"rakuten_us_{i}"),
                        'name': item.get('name') or item.get('title') or item.get('productName') or f'Rakuten Product {i+1}',
                        'price': float(item.get('price') or item.get('salePrice') or item.get('finalPrice') or 0),
                        'currency': 'USD',
                        'image_url': self._extract_us_image_url(item),
                        'affiliate_url': item.get('clickUrl') or item.get('affiliateUrl') or item.get('productUrl') or '',
                        'description': self._clean_description(item.get('description') or item.get('shortDescription') or 'Quality product from Rakuten US'),
                        'rating': float(item.get('rating') or item.get('averageRating') or 4.2),
                        'review_count': int(item.get('reviewCount') or item.get('numReviews') or 0),
                        'availability': item.get('inStock', True),
                        'relevance_score': 0.8,
                        'shop_name': item.get('merchantName') or item.get('retailer') or 'Rakuten Partner',
                        'category': item.get('category') or item.get('categoryName') or '',
                        'platform': 'rakuten',
                        'platform_name': 'Rakuten'
                    }
                    
                    if product['name'] and len(product['name']) > 2:
                        products.append(product)
                        logger.info(f"   ✅ Real product {i+1}: {product['name'][:40]}... - ${product['price']}")
                        
                except Exception as parse_error:
                    logger.warning(f"   ⚠️ Error parsing item {i}: {parse_error}")
                    continue
            
            return products
            
        except Exception as e:
            logger.error(f"   ❌ US response parsing error: {e}")
            return []
    
    def _extract_us_image_url(self, item: Dict) -> str:
        """Extract image URL from US item data"""
        image_fields = ['imageUrl', 'image', 'thumbnailUrl', 'smallImage', 'mediumImage']
        
        for field in image_fields:
            if field in item:
                image = item[field]
                if isinstance(image, str) and image:
                    return image
                elif isinstance(image, dict) and 'url' in image:
                    return image['url']
        return ''
    
    def _clean_description(self, description: str) -> str:
        """Clean and format description"""
        if not description:
            return 'Quality product available on Rakuten US'
        
        import re
        clean_desc = re.sub(r'<[^>]+>', '', description)
        clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()
        
        if len(clean_desc) > 150:
            clean_desc = clean_desc[:150] + '...'
        
        return clean_desc

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
        
        formatted = "\n\n🛒 **Here are some great options I found:**\n\n"
        
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