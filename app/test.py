import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def verify_backend_setup():
    """Run this function to verify your backend setup"""
    import sys
    
    print("🔍 Verifying AvatarCommerce Backend Setup...")
    
    # Check environment variables
    env_vars = {
        'OPENAI_API_KEY': os.getenv('OPENAI_API_KEY'),
        'HEYGEN_API_KEY': os.getenv('HEYGEN_API_KEY'),
        'SUPABASE_URL': os.getenv('SUPABASE_URL'),
        'SUPABASE_KEY': os.getenv('SUPABASE_KEY'),
        'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY')
    }
    
    missing_vars = [var for var, value in env_vars.items() if not value]
    
    if missing_vars:
        print(f"❌ Missing environment variables: {', '.join(missing_vars)}")
        return False
    else:
        print("✅ All required environment variables found")
    
    # Check required imports
    try:
        import flask
        import openai
        import supabase
        import jwt
        print("✅ All required packages installed")
    except ImportError as e:
        print(f"❌ Missing package: {e}")
        return False
    
    # Test database connection
    try:
        from database import Database
        db = Database()
        print("✅ Database connection successful")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False
    
    # Test OpenAI API
    try:
        import openai
        client = openai.OpenAI(api_key=env_vars['OPENAI_API_KEY'])
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "test"}],
            max_tokens=5
        )
        print("✅ OpenAI API connection successful")
    except Exception as e:
        print(f"❌ OpenAI API connection failed: {e}")
        return False
    
    print("🚀 Backend setup verification complete!")
    return True

if __name__ == '__main__':
    verify_backend_setup()