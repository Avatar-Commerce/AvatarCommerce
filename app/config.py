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

# FIXED: Updated Rakuten credentials to use Client ID and Client Secret
RAKUTEN_CLIENT_ID = os.getenv("RAKUTEN_CLIENT_ID")
RAKUTEN_CLIENT_SECRET = os.getenv("RAKUTEN_CLIENT_SECRET")
RAKUTEN_APPLICATION_ID = os.getenv("RAKUTEN_APPLICATION_ID")  # Optional

# Other affiliate platform credentials
AMAZON_ASSOCIATES_ACCESS_KEY = os.getenv("AMAZON_ASSOCIATES_ACCESS_KEY")
AMAZON_ASSOCIATES_SECRET_KEY = os.getenv("AMAZON_ASSOCIATES_SECRET_KEY")
AMAZON_ASSOCIATES_PARTNER_TAG = os.getenv("AMAZON_ASSOCIATES_PARTNER_TAG")
SHAREASALE_API_TOKEN = os.getenv("SHAREASALE_API_TOKEN")
SHAREASALE_SECRET_KEY = os.getenv("SHAREASALE_SECRET_KEY")
CJ_AFFILIATE_API_KEY = os.getenv("CJ_AFFILIATE_API_KEY")
SKIMLINKS_API_KEY = os.getenv("SKIMLINKS_API_KEY")
SKIMLINKS_PUBLISHER_ID = os.getenv("SKIMLINKS_PUBLISHER_ID")

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
    
    # Speech-to-text settings
    STT_MODEL = "whisper-1"  # OpenAI Whisper model
    STT_RESPONSE_FORMAT = "text"
    
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
    
    # Knowledge document storage
    KNOWLEDGE_STORAGE_BUCKET = "knowledge-documents"
    MAX_DOCUMENT_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_DOCUMENT_TYPES = [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ]

# UPDATED: Dynamic affiliate platform configurations with correct Rakuten structure
AFFILIATE_PLATFORMS = {}

# FIXED: Add Rakuten if Client ID and Client Secret are available
if RAKUTEN_CLIENT_ID and RAKUTEN_CLIENT_SECRET:
    AFFILIATE_PLATFORMS['rakuten'] = {
        'name': 'Rakuten Advertising',
        'base_url': 'https://api.rakutenadvertising.com/productsearch/v1',
        'auth_url': 'https://api.rakutenadvertising.com/auth/token',
        'credentials': {
            'client_id': RAKUTEN_CLIENT_ID,
            'client_secret': RAKUTEN_CLIENT_SECRET,
            'application_id': RAKUTEN_APPLICATION_ID  # Optional
        },
        'auth_type': 'oauth2_client_credentials',
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
        'auth_type': 'aws_signature_v4',
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
        'auth_type': 'hmac_signature',
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
        'auth_type': 'bearer_token',
        'enabled': True
    }

# Add Skimlinks if credentials are available
if SKIMLINKS_API_KEY:
    AFFILIATE_PLATFORMS['skimlinks'] = {
        'name': 'Skimlinks',
        'base_url': 'https://api-2.skimlinks.com',
        'credentials': {
            'api_key': SKIMLINKS_API_KEY,
            'publisher_id': SKIMLINKS_PUBLISHER_ID
        },
        'auth_type': 'bearer_token',
        'enabled': True
    }

# UPDATED: All available affiliate platforms with their requirements
ALL_AFFILIATE_PLATFORMS = {
    'rakuten': {
        'name': 'Rakuten Advertising',
        'enabled': 'rakuten' in AFFILIATE_PLATFORMS,
        'required_fields': ['client_id', 'client_secret'],
        'optional_fields': ['application_id'],
        'description': 'Global leader in affiliate marketing with premium brands',
        'commission_range': '2-15%',
        'min_payout': '$50'
    },
    'amazon': {
        'name': 'Amazon Associates',
        'enabled': 'amazon' in AFFILIATE_PLATFORMS,
        'required_fields': ['access_key', 'secret_key', 'partner_tag'],
        'optional_fields': [],
        'description': 'World\'s largest online retailer with millions of products',
        'commission_range': '1-10%',
        'min_payout': '$10'
    },
    'shareasale': {
        'name': 'ShareASale',
        'enabled': 'shareasale' in AFFILIATE_PLATFORMS,
        'required_fields': ['api_token', 'secret_key', 'affiliate_id'],
        'optional_fields': [],
        'description': 'Performance marketing network with diverse merchants',
        'commission_range': '3-20%',
        'min_payout': '$50'
    },
    'cj_affiliate': {
        'name': 'CJ Affiliate',
        'enabled': 'cj_affiliate' in AFFILIATE_PLATFORMS,
        'required_fields': ['api_key', 'website_id'],
        'optional_fields': [],
        'description': 'Commission Junction - trusted by top brands worldwide',
        'commission_range': '2-12%',
        'min_payout': '$50'
    },
    'skimlinks': {
        'name': 'Skimlinks',
        'enabled': 'skimlinks' in AFFILIATE_PLATFORMS,
        'required_fields': ['api_key', 'publisher_id'],
        'optional_fields': [],
        'description': 'Automated affiliate marketing with 48,500+ merchants',
        'commission_range': '1-8%',
        'min_payout': '$10'
    }
}

def get_enabled_platforms():
    """Get list of currently enabled affiliate platforms"""
    return list(AFFILIATE_PLATFORMS.keys())

def is_platform_enabled(platform):
    """Check if a specific platform is enabled"""
    return platform in AFFILIATE_PLATFORMS

def get_platform_config(platform):
    """Get configuration for a specific platform"""
    return AFFILIATE_PLATFORMS.get(platform)

def get_platform_credentials_template(platform):
    """Get the required credentials template for a platform"""
    templates = {
        'rakuten': {
            'client_id': 'Your Rakuten Client ID',
            'client_secret': 'Your Rakuten Client Secret',
            'application_id': 'Your Application ID (optional)'
        },
        'amazon': {
            'access_key': 'Your AWS Access Key (AKIA...)',
            'secret_key': 'Your AWS Secret Key',
            'partner_tag': 'Your Associate Tag (yoursite-20)'
        },
        'shareasale': {
            'api_token': 'Your ShareASale API Token',
            'secret_key': 'Your ShareASale Secret Key',
            'affiliate_id': 'Your ShareASale Affiliate ID'
        },
        'cj_affiliate': {
            'api_key': 'Your CJ Affiliate API Key',
            'website_id': 'Your CJ Website ID'
        },
        'skimlinks': {
            'api_key': 'Your Skimlinks API Key',
            'publisher_id': 'Your Skimlinks Publisher ID'
        }
    }
    return templates.get(platform, {})

# Knowledge and RAG settings
class KnowledgeConfig:
    """Configuration for knowledge base and RAG functionality"""
    
    # Embedding model settings
    EMBEDDING_MODEL = "all-MiniLM-L6-v2"  # Sentence transformers model
    OPENAI_EMBEDDING_MODEL = "text-embedding-3-small"  # OpenAI embedding model
    
    # Text chunking settings
    MAX_CHUNK_SIZE = 500  # Maximum tokens per chunk
    CHUNK_OVERLAP = 50   # Overlap between chunks
    MIN_CHUNK_SIZE = 100  # Minimum tokens per chunk
    
    # Search settings
    SIMILARITY_THRESHOLD = 0.3  # Minimum similarity for relevant results
    MAX_SEARCH_RESULTS = 5     # Maximum number of search results
    
    # Document processing settings
    MAX_DOCUMENT_SIZE = 10 * 1024 * 1024  # 10MB
    SUPPORTED_FORMATS = ['pdf', 'docx', 'doc', 'txt']
    
    # Personal knowledge fields
    PERSONAL_FIELDS = ['bio', 'expertise', 'personality']
    MAX_BIO_LENGTH = 1000
    MAX_EXPERTISE_LENGTH = 500
    MAX_PERSONALITY_LENGTH = 500

# Voice and Audio settings
class AudioConfig:
    """Configuration for voice and audio functionality"""
    
    # OpenAI TTS settings
    OPENAI_TTS_MODEL = "tts-1-hd"  # Use HD model for better quality
    OPENAI_TTS_SPEED = 0.9  # Slightly slower for clarity
    
    # Voice mapping for different services
    VOICE_MAPPINGS = {
        'openai': {
            '2d5b0e6cf36f460aa7fc47e3eee4ba54': 'nova',    # Female professional (Rachel)
            'd7bbcdd6964c47bdaae26decade4a933': 'onyx',    # Male professional (David)
            '4d2b8e6cf36f460aa7fc47e3eee4ba12': 'shimmer', # Female friendly (Emma)
            '3a1c7d5bf24e350bb6dc46e2dee3ab21': 'echo',    # Male casual (Michael)
            '1bd001e7e50f421d891986aad5158bc8': 'alloy',   # Female warm (Olivia)
        },
        'elevenlabs': {
            '2d5b0e6cf36f460aa7fc47e3eee4ba54': '21m00Tcm4TlvDq8ikWAM',  # Rachel
            'd7bbcdd6964c47bdaae26decade4a933': 'VR6AewLTigWG4xSOukaG',  # David
            '4d2b8e6cf36f460aa7fc47e3eee4ba12': 'ErXwobaYiN019PkySvjV',  # Emma
            '3a1c7d5bf24e350bb6dc46e2dee3ab21': 'VR6AewLTigWG4xSOukaG',  # Michael
            '1bd001e7e50f421d891986aad5158bc8': 'oWAxZDx7w5VEj9dCyTzz',  # Olivia
        }
    }
    
    # Speech-to-text settings
    STT_MODEL = "whisper-1"
    STT_RESPONSE_FORMAT = "text"
    STT_LANGUAGE = "en"
    
    # Audio processing settings
    MAX_AUDIO_SIZE = 25 * 1024 * 1024  # 25MB (OpenAI Whisper limit)
    SUPPORTED_AUDIO_FORMATS = ['mp3', 'wav', 'webm', 'm4a', 'ogg']
    
    # Voice preparation settings
    MAX_VOICE_TEXT_LENGTH = 400  # Maximum characters for voice generation
    VOICE_SENTENCE_LIMIT = 4     # Maximum sentences for voice responses

# Environment validation
def validate_environment():
    """Validate that required environment variables are set"""
    required_vars = {
        'SUPABASE_URL': SUPABASE_URL,
        'SUPABASE_KEY': SUPABASE_KEY,
        'OPENAI_API_KEY': OPENAI_API_KEY,
        'HEYGEN_API_KEY': HEYGEN_API_KEY,
        'JWT_SECRET_KEY': JWT_SECRET_KEY
    }
    
    missing = [var for var, value in required_vars.items() if not value]
    
    if missing:
        raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
    
    print("✅ Core environment variables validated")
    
    # Check optional affiliate platform credentials
    affiliate_status = {}
    for platform, config in ALL_AFFILIATE_PLATFORMS.items():
        affiliate_status[platform] = config['enabled']
    
    enabled_platforms = [p for p, enabled in affiliate_status.items() if enabled]
    if enabled_platforms:
        print(f"✅ Affiliate platforms enabled: {', '.join(enabled_platforms)}")
    else:
        print("⚠️ No affiliate platforms configured - product recommendations will be limited")
    
    return True

# Database table configurations for knowledge management
DATABASE_SCHEMA = {
    'knowledge_documents': {
        'id': 'UUID PRIMARY KEY',
        'influencer_id': 'TEXT REFERENCES influencers(id)',
        'filename': 'TEXT NOT NULL',
        'safe_filename': 'TEXT NOT NULL',
        'content_type': 'TEXT NOT NULL',
        'file_size': 'INTEGER NOT NULL',
        'upload_date': 'TIMESTAMP DEFAULT NOW()',
        'is_processed': 'BOOLEAN DEFAULT FALSE',
        'processed_date': 'TIMESTAMP',
        'text_content': 'TEXT',
        'chunk_count': 'INTEGER DEFAULT 0',
        'created_at': 'TIMESTAMP DEFAULT NOW()',
        'updated_at': 'TIMESTAMP DEFAULT NOW()'
    },
    'knowledge_chunks': {
        'id': 'UUID PRIMARY KEY DEFAULT gen_random_uuid()',
        'document_id': 'UUID REFERENCES knowledge_documents(id) ON DELETE CASCADE',
        'influencer_id': 'TEXT REFERENCES influencers(id)',
        'chunk_index': 'INTEGER NOT NULL',
        'chunk_text': 'TEXT NOT NULL',
        'embedding': 'TEXT',  # Stored as JSON string for compatibility
        'token_count': 'INTEGER',
        'created_at': 'TIMESTAMP DEFAULT NOW()'
    },
    'affiliate_links': {
        'id': 'UUID PRIMARY KEY',
        'influencer_id': 'TEXT REFERENCES influencers(id)',
        'platform': 'TEXT NOT NULL',
        'is_active': 'BOOLEAN DEFAULT TRUE',
        # Amazon fields
        'amazon_access_key': 'TEXT',
        'amazon_secret_key': 'TEXT',
        'partner_tag': 'TEXT',
        # Rakuten fields (UPDATED)
        'rakuten_client_id': 'TEXT',
        'rakuten_client_secret': 'TEXT',
        'rakuten_application_id': 'TEXT',
        # ShareASale fields
        'shareasale_api_token': 'TEXT',
        'shareasale_secret_key': 'TEXT',
        # CJ Affiliate fields
        'cj_api_key': 'TEXT',
        'website_id': 'TEXT',
        # Skimlinks fields
        'skimlinks_api_key': 'TEXT',
        'publisher_id': 'TEXT',
        # Common fields
        'affiliate_id': 'TEXT',
        'merchant_id': 'TEXT',  # Legacy field
        'api_token': 'TEXT',    # Legacy field
        'created_at': 'TIMESTAMP DEFAULT NOW()',
        'updated_at': 'TIMESTAMP DEFAULT NOW()'
    }
}

# API endpoint configurations
API_ENDPOINTS = {
    'chat': '/api/chat',
    'chat_info': '/api/chat/<username>',
    'speech_to_text': '/api/speech-to-text',
    'knowledge_upload': '/api/knowledge/upload',
    'knowledge_personal': '/api/knowledge/personal-info',
    'affiliate_connect': '/api/affiliate',
    'affiliate_test': '/api/affiliate/test-connection',
    'affiliate_search': '/api/affiliate/search-products',
    'avatar_create': '/api/avatar/create',
    'avatar_test_video': '/api/avatar/test-video',
    'voice_preference': '/api/voice/preference'
}

# Default platform data for frontend
DEFAULT_PLATFORM_DATA = {
    'amazon': {
        'name': 'Amazon Associates',
        'logo': 'A',
        'description': 'World\'s largest online retailer with millions of products',
        'commission_range': '1-10%',
        'min_payout': '$10',
        'payment_schedule': 'Monthly',
        'special_features': ['Product reviews', 'Prime eligibility', 'Lightning deals'],
        'setup_guide': {
            'title': 'Amazon Associates Setup',
            'steps': [
                'Log in to your Amazon Associates account',
                'Go to Tools → Product Advertising API',
                'Copy your Access Key, Secret Key, and Associate Tag',
                'Paste them in the form below'
            ]
        }
    },
    'rakuten': {
        'name': 'Rakuten Advertising',
        'logo': 'R',
        'description': 'Global leader in affiliate marketing with premium brands',
        'commission_range': '2-15%',
        'min_payout': '$50',
        'payment_schedule': 'Monthly',
        'special_features': ['Premium brands', 'Global reach', 'Advanced analytics'],
        'setup_guide': {
            'title': 'Rakuten Advertising Setup',
            'steps': [
                'Log in to your Rakuten Advertising account',
                'Navigate to Developer → API Access or App Management',
                'Copy your Client ID and Client Secret',
                'Also get your Application ID if available',
                'Enter them in the form below'
            ]
        }
    },
    'shareasale': {
        'name': 'ShareASale',
        'logo': 'S',
        'description': 'Performance marketing network with diverse merchants',
        'commission_range': '3-20%',
        'min_payout': '$50',
        'payment_schedule': '20th of each month',
        'special_features': ['Real-time tracking', 'Custom links', 'Merchant variety'],
        'setup_guide': {
            'title': 'ShareASale Setup',
            'steps': [
                'Log in to your ShareASale account',
                'Go to Tools → API Documentation',
                'Generate or find your API Token and Secret Key',
                'Also note your Affiliate ID from your account dashboard'
            ]
        }
    },
    'cj_affiliate': {
        'name': 'CJ Affiliate',
        'logo': 'CJ',
        'description': 'Commission Junction - trusted by top brands worldwide',
        'commission_range': '2-12%',
        'min_payout': '$50',
        'payment_schedule': 'Monthly',
        'special_features': ['Enterprise brands', 'Deep linking', 'Attribution tracking'],
        'setup_guide': {
            'title': 'CJ Affiliate Setup',
            'steps': [
                'Log in to your CJ Affiliate account',
                'Visit the Developer Portal',
                'Generate an API Key for Product Search',
                'Find your Website ID in account settings'
            ]
        }
    },
    'skimlinks': {
        'name': 'Skimlinks',
        'logo': 'SK',
        'description': 'Automated affiliate marketing with 48,500+ merchants',
        'commission_range': '1-8%',
        'min_payout': '$10',
        'payment_schedule': 'Monthly',
        'special_features': ['Auto-affiliate', 'Content monetization', 'Easy setup'],
        'setup_guide': {
            'title': 'Skimlinks Setup',
            'steps': [
                'Log in to Skimlinks Hub',
                'Go to Developer Tools → API Access',
                'Generate an API Key',
                'Copy your Publisher ID from account settings'
            ]
        }
    }
}

# Logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'default': {
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
        },
        'file': {
            'level': 'DEBUG',
            'formatter': 'standard',
            'class': 'logging.FileHandler',
            'filename': 'logs/avatar_commerce.log',
            'mode': 'a',
        },
    },
    'loggers': {
        '': {
            'handlers': ['default', 'file'],
            'level': 'DEBUG',
            'propagate': False
        }
    }
}