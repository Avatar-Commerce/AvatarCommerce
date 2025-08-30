import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Application configuration class"""
    
    # Core API Keys
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    HEYGEN_API_KEY = os.getenv("HEYGEN_API_KEY")
    ELEVEN_LABS_API_KEY = os.getenv("ELEVEN_LABS_API_KEY")
    
    # Database Configuration
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")
    SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    
    # JWT Security
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
    JWT_EXPIRATION_DAYS = 30
    
    # File Upload Settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'mp4', 'mov', 'mp3', 'wav', 'pdf', 'docx', 'txt'}
    
    # Voice Configuration
    DEFAULT_VOICE_ID = "2d5b0e6cf36f460aa7fc47e3eee4ba54"
    
    # OpenAI TTS Voice Mapping
    VOICE_MAPPING = {
        '2d5b0e6cf36f460aa7fc47e3eee4ba54': 'nova',    # Rachel (Professional)
        'd7bbcdd6964c47bdaae26decade4a933': 'onyx',    # David (Professional)
        '4d2b8e6cf36f460aa7fc47e3eee4ba12': 'shimmer', # Emma (Friendly)
        '3a1c7d5bf24e350bb6dc46e2dee3ab21': 'echo',    # Michael (Casual)
        '1bd001e7e50f421d891986aad5158bc8': 'alloy',   # Olivia (Warm)
    }
    
    # Audio Processing
    MAX_VOICE_TEXT_LENGTH = 400
    MAX_AUDIO_SIZE = 25 * 1024 * 1024  # 25MB for Whisper
    
    # Knowledge Documents
    MAX_DOCUMENT_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_CHUNK_SIZE = 500
    CHUNK_OVERLAP = 50
    
    @classmethod
    def validate(cls):
        """Validate required environment variables"""
        required_vars = [
            'SUPABASE_URL', 'SUPABASE_KEY', 'OPENAI_API_KEY', 'HEYGEN_API_KEY'
        ]
        
        missing = []
        for var in required_vars:
            if not getattr(cls, var):
                missing.append(var)
        
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
        
        print("Configuration validated successfully")

# Backwards compatibility exports
OPENAI_API_KEY = Config.OPENAI_API_KEY
HEYGEN_API_KEY = Config.HEYGEN_API_KEY
SUPABASE_URL = Config.SUPABASE_URL
SUPABASE_KEY = Config.SUPABASE_KEY
JWT_SECRET_KEY = Config.JWT_SECRET_KEY