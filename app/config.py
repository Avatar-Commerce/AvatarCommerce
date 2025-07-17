import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Individual variables (backwards compatibility)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
HEYGEN_API_KEY = os.getenv("HEYGEN_API_KEY")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default-secret-key")
SUPABASE_SERVICE_ROLE_KEY = os.getenv('SUPABASE_SERVICE_ROLE_KEY')
ELEVEN_LABS_API_KEY = os.getenv("ELEVEN_LABS_API_KEY") 

# Multiple affiliate platform credentials (optional)
RAKUTEN_MERCHANT_ID = os.getenv("RAKUTEN_MERCHANT_ID")
RAKUTEN_TOKEN = os.getenv("RAKUTEN_TOKEN")
AMAZON_ASSOCIATES_ACCESS_KEY = os.getenv("AMAZON_ASSOCIATES_ACCESS_KEY")
AMAZON_ASSOCIATES_SECRET_KEY = os.getenv("AMAZON_ASSOCIATES_SECRET_KEY")
AMAZON_ASSOCIATES_PARTNER_TAG = os.getenv("AMAZON_ASSOCIATES_PARTNER_TAG")
SHAREASALE_API_TOKEN = os.getenv("SHAREASALE_API_TOKEN")
SHAREASALE_SECRET_KEY = os.getenv("SHAREASALE_SECRET_KEY")
CJ_AFFILIATE_API_KEY = os.getenv("CJ_AFFILIATE_API_KEY")

# Config class for chatbot.py compatibility
class Config:
    """Application configuration class"""
    
    # Environment variables
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")
    SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    HEYGEN_API_KEY = os.getenv("HEYGEN_API_KEY")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default-secret-key")
    ELEVEN_LABS_API_KEY = os.getenv("ELEVEN_LABS_API_KEY")
    
    # Application settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'pdf', 'doc', 'docx'}
    JWT_EXPIRATION_DAYS = 30
    
    # API settings
    HEYGEN_API_BASE = "https://api.heygen.com"
    DEFAULT_VOICE_ID = "2d5b0e6cf36f460aa7fc47e3eee4ba54"
    
    @classmethod
    def validate(cls):
        """Validate required environment variables"""
        required_vars = [
            'SUPABASE_URL', 'SUPABASE_KEY', 'HEYGEN_API_KEY', 
            'OPENAI_API_KEY', 'JWT_SECRET_KEY'
        ]
        missing = [var for var in required_vars if not getattr(cls, var)]
        if missing:
            raise ValueError(f"Missing required environment variables: {missing}")

# Dynamic affiliate platform configurations - only include if credentials are available
AFFILIATE_PLATFORMS = {}

# Add Rakuten if credentials are available
if RAKUTEN_MERCHANT_ID and RAKUTEN_TOKEN:
    AFFILIATE_PLATFORMS['rakuten'] = {
        'name': 'Rakuten',
        'base_url': 'https://api.rakuten.co.jp/rws/3.0/search/product',
        'credentials': {
            'merchant_id': RAKUTEN_MERCHANT_ID,
            'token': RAKUTEN_TOKEN
        },
        'enabled': True
    }

# Add Amazon if credentials are available
if AMAZON_ASSOCIATES_ACCESS_KEY and AMAZON_ASSOCIATES_SECRET_KEY and AMAZON_ASSOCIATES_PARTNER_TAG:
    AFFILIATE_PLATFORMS['amazon'] = {
        'name': 'Amazon Associates',
        'base_url': 'https://webservices.amazon.com/paapi5/searchitems',
        'credentials': {
            'access_key': AMAZON_ASSOCIATES_ACCESS_KEY,
            'secret_key': AMAZON_ASSOCIATES_SECRET_KEY,
            'partner_tag': AMAZON_ASSOCIATES_PARTNER_TAG
        },
        'enabled': True
    }

# Add ShareASale if credentials are available
if SHAREASALE_API_TOKEN and SHAREASALE_SECRET_KEY:
    AFFILIATE_PLATFORMS['shareasale'] = {
        'name': 'ShareASale',
        'base_url': 'https://api.shareasale.com/w.cfm',
        'credentials': {
            'api_token': SHAREASALE_API_TOKEN,
            'secret_key': SHAREASALE_SECRET_KEY
        },
        'enabled': True
    }

# Add CJ Affiliate if credentials are available
if CJ_AFFILIATE_API_KEY:
    AFFILIATE_PLATFORMS['cj_affiliate'] = {
        'name': 'CJ Affiliate (Commission Junction)',
        'base_url': 'https://product-search.api.cj.com/v2/product-search',
        'credentials': {
            'api_key': CJ_AFFILIATE_API_KEY
        },
        'enabled': True
    }

# Always include these platforms as placeholders (even if not configured yet)
ALL_AFFILIATE_PLATFORMS = {
    'rakuten': {'name': 'Rakuten', 'enabled': 'rakuten' in AFFILIATE_PLATFORMS},
    'amazon': {'name': 'Amazon Associates', 'enabled': 'amazon' in AFFILIATE_PLATFORMS},
    'shareasale': {'name': 'ShareASale', 'enabled': 'shareasale' in AFFILIATE_PLATFORMS},
    'cj_affiliate': {'name': 'CJ Affiliate', 'enabled': 'cj_affiliate' in AFFILIATE_PLATFORMS}
}

def get_enabled_platforms():
    """Get list of currently enabled affiliate platforms"""
    return list(AFFILIATE_PLATFORMS.keys())

def is_platform_enabled(platform):
    """Check if a specific platform is enabled"""
    return platform in AFFILIATE_PLATFORMS