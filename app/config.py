import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

APIFY_API_KEY = os.getenv("APIFY_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
HEYGEN_API_KEY = os.getenv("HEYGEN_API_KEY")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default-secret-key")  # Add this line



#Docker was updated