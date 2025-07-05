#!/usr/bin/env python3
"""
AvatarCommerce Main Application
A platform for influencers to create AI-powered avatars for audience engagement
"""

import os
import sys
import uuid
import hashlib
import tempfile
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional, Dict, Any

import jwt
import requests
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

# Import custom modules
try:
    from database import Database
    from chatbot import Chatbot
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("Please ensure all required modules are in the app directory")
    sys.exit(1)

# =============================================================================
# APPLICATION CONFIGURATION
# =============================================================================

class Config:
    """Application configuration"""
    
    # Environment variables
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")
    SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    HEYGEN_API_KEY = os.getenv("HEYGEN_API_KEY")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    
    # Application settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
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

# =============================================================================
# APPLICATION SETUP
# =============================================================================

def create_app():
    """Create and configure Flask application"""
    
    # Validate configuration
    Config.validate()
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = Config.JWT_SECRET_KEY
    app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH
    
    # Configure CORS
    CORS(app, 
         resources={r"/api/*": {
             "origins": "*",
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization", "Accept"],
             "supports_credentials": False
         }})
    
    # Handle preflight OPTIONS requests
    @app.before_request
    def handle_options():
        if request.method == "OPTIONS":
            response = make_response()
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, Accept"
            return response
    
    # Setup logging
    setup_logging()
    
    return app

def setup_logging():
    """Configure application logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('app.log') if os.access('.', os.W_OK) else logging.NullHandler()
        ]
    )

# =============================================================================
# GLOBAL INSTANCES
# =============================================================================

app = create_app()
logger = logging.getLogger(__name__)

# Initialize database and chatbot
try:
    db = Database()
    chatbot = Chatbot(db)
    logger.info("✅ Database and chatbot initialized successfully")
except Exception as e:
    logger.error(f"❌ Failed to initialize database/chatbot: {e}")
    sys.exit(1)

# =============================================================================
# AUTHENTICATION & MIDDLEWARE
# =============================================================================

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Extract token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({
                'status': 'error',
                'message': 'Authentication token is required'
            }), 401
        
        try:
            # Decode token
            data = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=["HS256"])
            
            # Get current user
            current_user = db.get_influencer_by_username(data['username'])
            if not current_user:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid token: user not found'
                }), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({
                'status': 'error',
                'message': 'Token has expired'
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'status': 'error',
                'message': 'Invalid token'
            }), 401
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return jsonify({
                'status': 'error',
                'message': 'Token validation failed'
            }), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def validate_file_upload(file):
    """Validate uploaded file"""
    if not file or file.filename == '':
        raise ValueError("No file selected")
    
    if not allowed_file(file.filename):
        raise ValueError(f"Invalid file type. Allowed: {', '.join(Config.ALLOWED_EXTENSIONS)}")
    
    # Check file size (additional check beyond Flask's MAX_CONTENT_LENGTH)
    try:
        file.seek(0, 2)  # Seek to end
        size = file.tell()
        file.seek(0)  # Reset
        
        if size > 10 * 1024 * 1024:  # 10MB
            raise ValueError("File too large. Maximum size: 10MB")
        
        if size == 0:
            raise ValueError("File is empty")
            
    except Exception as e:
        raise ValueError(f"Could not read file: {str(e)}")
    
    return True

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_jwt_token(user_data):
    """Generate JWT token for user"""
    from datetime import timezone
    
    payload = {
        'username': user_data['username'],
        'id': user_data['id'],
        'user_type': 'influencer',
        'exp': datetime.now(timezone.utc) + timedelta(days=Config.JWT_EXPIRATION_DAYS)
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm="HS256")

# =============================================================================
# HEYGEN API INTEGRATION
# =============================================================================

class HeyGenAPI:
    @staticmethod
    def create_photo_avatar(image_file):
        """Create talking photo avatar from uploaded image using correct HeyGen API"""
        logger.info("🎬 Creating talking photo avatar from uploaded image")
        
        # Read file content
        try:
            image_file.seek(0)
            file_content = image_file.read()
            filename = getattr(image_file, 'filename', 'avatar.jpg')
            
            logger.info(f"📁 File: {filename}")
            logger.info(f"📊 Size: {len(file_content)} bytes")
            
            if len(file_content) == 0:
                raise Exception("File is empty")
                
        except Exception as e:
            raise Exception(f"Failed to read file: {str(e)}")
        
        # Upload image to HeyGen Talking Photo endpoint
        headers = {
            "x-api-key": Config.HEYGEN_API_KEY,
            "Content-Type": "image/jpeg"
        }
        
        try:
            logger.info("📤 Uploading image to HeyGen Talking Photo API...")
            
            response = requests.post(
                "https://upload.heygen.com/v1/talking_photo",
                headers=headers,
                data=file_content,
                timeout=60
            )
            
            logger.info(f"📥 Upload response: {response.status_code}")
            logger.info(f"📋 Upload response body: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                
                # CRITICAL FIX: Parse the correct response format
                if result.get('code') == 100 and result.get('data'):
                    data = result.get('data', {})
                    talking_photo_id = data.get('talking_photo_id')
                    
                    if talking_photo_id:
                        logger.info(f"✅ Talking photo created successfully: {talking_photo_id}")
                        
                        return {
                            "avatar_id": talking_photo_id,
                            "status": "ready",
                            "type": "talking_photo",
                            "method": "talking_photo_upload"
                        }
                    else:
                        logger.error("No talking_photo_id in response")
                        raise Exception("No talking photo ID returned")
                else:
                    error_msg = result.get('message', 'Upload failed')
                    logger.error(f"Upload failed: {error_msg}")
                    raise Exception(f"Upload failed: {error_msg}")
            else:
                error_msg = f"Upload failed: {response.status_code} - {response.text}"
                logger.error(error_msg)
                raise Exception(error_msg)
                
        except Exception as e:
            logger.error(f"Talking photo creation failed: {str(e)}")
            raise e  # Re-raise the exception instead of falling back

    @staticmethod
    def _create_avatar_group_from_asset(asset_id, asset_url):
        """Create avatar group from uploaded asset"""
        
        headers = {
            "Content-Type": "application/json",
            "X-Api-Key": Config.HEYGEN_API_KEY
        }
        
        # Create image_key format that HeyGen expects
        image_key = f"image/{asset_id}/original"
        
        payload = {
            "name": f"avatar_{int(time.time())}",
            "image_key": image_key
        }
        
        try:
            logger.info("👥 Creating avatar group...")
            
            response = requests.post(
                "https://api.heygen.com/v2/photo_avatar/avatar_group/create",
                headers=headers,
                json=payload,
                timeout=60
            )
            
            logger.info(f"Group creation response: {response.status_code}")
            logger.info(f"Group creation body: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                
                if not result.get('error'):
                    data = result.get('data', {})
                    group_id = data.get('id') or data.get('group_id')
                    
                    if group_id:
                        logger.info(f"✅ Avatar group created: {group_id}")
                        
                        # Try to get avatar looks from the group
                        looks_result = HeyGenAPI._get_avatar_looks(group_id)
                        
                        if looks_result['success'] and looks_result['avatar_looks']:
                            # Use first available avatar look
                            avatar_look = looks_result['avatar_looks'][0]
                            avatar_id = avatar_look['id']
                            
                            return {
                                "success": True,
                                "avatar_id": avatar_id,
                                "group_id": group_id
                            }
                        else:
                            # Use group_id as avatar_id if no looks available yet
                            return {
                                "success": True,
                                "avatar_id": group_id,
                                "group_id": group_id
                            }
                            
                error_msg = result.get('error', {}).get('message', 'Group creation failed')
                return {"success": False, "error": error_msg}
            else:
                return {"success": False, "error": f"HTTP {response.status_code}: {response.text}"}
                
        except Exception as e:
            return {"success": False, "error": f"Group creation error: {str(e)}"}
        
    @staticmethod  
    def _get_avatar_looks(group_id):
        """Get available avatar looks from group"""
        
        headers = {
            "Accept": "application/json",
            "X-Api-Key": Config.HEYGEN_API_KEY
        }
        
        try:
            response = requests.get(
                f"https://api.heygen.com/v2/photo_avatar/avatar_group/{group_id}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if not result.get('error'):
                    data = result.get('data', {})
                    avatar_list = data.get('avatar_list', [])
                    
                    # Filter for completed/ready avatars
                    ready_avatars = [
                        avatar for avatar in avatar_list 
                        if avatar.get('status') in ['completed', 'ready', 'success']
                    ]
                    
                    return {
                        "success": True,
                        "avatar_looks": ready_avatars or avatar_list  # Use all if none ready
                    }
                    
            return {"success": False, "error": "No avatar looks found"}
            
        except Exception as e:
            return {"success": False, "error": f"Get looks error: {str(e)}"}
    
    @staticmethod
    def _create_via_asset_upload(file_content, filename, headers):
        """Create avatar via asset upload method"""
        try:
            # Step 1: Upload asset
            files = {
                'file': (
                    secure_filename(filename),
                    file_content,
                    'image/jpeg'
                )
            }
            
            asset_response = requests.post(
                "https://api.heygen.com/v1/asset/upload",
                headers=headers,
                files=files,
                timeout=60
            )
            
            logger.info(f"Asset upload response: {asset_response.status_code}")
            logger.info(f"Asset upload body: {asset_response.text}")
            
            if asset_response.status_code == 200:
                asset_result = asset_response.json()
                asset_id = asset_result.get("data", {}).get("id")
                asset_url = asset_result.get("data", {}).get("url")
                
                if asset_id:
                    logger.info(f"Asset uploaded successfully: {asset_id}")
                    
                    # Step 2: Create talking photo with asset
                    avatar_payload = {
                        "name": f"avatar_{int(datetime.now().timestamp())}",
                        "image_url": asset_url
                    }
                    
                    avatar_headers = {
                        **headers,
                        "Content-Type": "application/json"
                    }
                    
                    avatar_response = requests.post(
                        "https://api.heygen.com/v2/talking_photo",
                        headers=avatar_headers,
                        json=avatar_payload,
                        timeout=60
                    )
                    
                    logger.info(f"Avatar creation response: {avatar_response.status_code}")
                    logger.info(f"Avatar creation body: {avatar_response.text}")
                    
                    if avatar_response.status_code == 200:
                        avatar_result = avatar_response.json()
                        if not avatar_result.get("error"):
                            avatar_id = avatar_result.get("data", {}).get("id")
                            if avatar_id:
                                logger.info(f"Avatar created via asset upload: {avatar_id}")
                                return {
                                    "avatar_id": avatar_id,
                                    "status": "processing",
                                    "type": "talking_photo"
                                }
            
        except Exception as e:
            logger.warning(f"Asset upload method failed: {e}")
            
    @staticmethod
    def select_fallback_avatar():
        """Select a pre-made avatar as fallback when custom creation fails"""
        try:
            headers = {
                "X-Api-Key": Config.HEYGEN_API_KEY,
                "Accept": "application/json"
            }
            
            response = requests.get(
                "https://api.heygen.com/v2/avatars",
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                avatars = data.get("data", {}).get("avatars", [])
                
                if avatars:
                    # Select a good default avatar (prefer first available)
                    selected_avatar = avatars[0]
                    
                    return {
                        'avatar_id': selected_avatar.get('avatar_id'),
                        'name': selected_avatar.get('name', 'Default Avatar'),
                        'gender': selected_avatar.get('gender', 'Unknown')
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Fallback avatar selection failed: {e}")
            return None
    
    @staticmethod
    def check_avatar_status(avatar_id):
        """Check photo avatar status"""
        headers = {
            "X-Api-Key": Config.HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        try:
            response = requests.get(
                f"{Config.HEYGEN_API_BASE}/v2/photo_avatar/{avatar_id}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                avatar_data = result.get("data", {})
                
                return {
                    "exists": True,
                    "status": avatar_data.get("status", "unknown"),
                    "ready": avatar_data.get("status") == "completed"
                }
            else:
                return {
                    "exists": False,
                    "status": "not_found",
                    "ready": False
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Avatar status check failed: {e}")
            return {
                "exists": False,
                "status": "error",
                "ready": False
            }

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'status': 'error',
        'message': 'Bad request'
    }), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        'status': 'error',
        'message': 'Unauthorized access'
    }), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'status': 'error',
        'message': 'Resource not found'
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'status': 'error',
        'message': 'Method not allowed'
    }), 405

@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def file_too_large(error):
    return jsonify({
        'status': 'error',
        'message': 'File too large. Maximum size: 16MB'
    }), 413

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'status': 'error',
        'message': 'Internal server error'
    }), 500

# =============================================================================
# API ROUTES
# =============================================================================

# Health Check
@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'success',
        'message': 'AvatarCommerce API is running',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '2.0'
    })

# Authentication Routes (with legacy endpoints for frontend compatibility)
@app.route('/api/register', methods=['POST'])
@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register new influencer account"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({
                'status': 'error',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        username = data['username'].strip()
        email = data['email'].strip().lower()
        password = data['password']
        
        # Validate username format
        if not username.replace('_', '').isalnum():
            return jsonify({
                'status': 'error',
                'message': 'Username can only contain letters, numbers, and underscores'
            }), 400
        
        # Check if user already exists
        if db.get_influencer_by_username(username):
            return jsonify({
                'status': 'error',
                'message': 'Username already exists'
            }), 400
        
        if db.get_influencer_by_email(email):
            return jsonify({
                'status': 'error',
                'message': 'Email already exists'
            }), 400
        
        # Create user
        user_data = {
            'id': str(uuid.uuid4()),
            'username': username,
            'email': email,
            'password_hash': hash_password(password),
            'bio': data.get('bio', ''),
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        created_user = db.create_influencer(user_data)
        if not created_user:
            return jsonify({
                'status': 'error',
                'message': 'Failed to create account'
            }), 500
        
        # Generate token
        token = generate_jwt_token(created_user)
        
        return jsonify({
            'status': 'success',
            'message': 'Account created successfully',
            'data': {
                'user': {
                    'id': created_user['id'],
                    'username': created_user['username'],
                    'email': created_user['email']
                },
                'token': token
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Registration failed'
        }), 500

@app.route('/api/login', methods=['POST'])
@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login influencer"""
    try:
        data = request.get_json()
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({
                'status': 'error',
                'message': 'Username and password are required'
            }), 400
        
        # Get user
        user = db.get_influencer_by_username(username)
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'Invalid credentials'
            }), 401
        
        # Verify password
        if user['password_hash'] != hash_password(password):
            return jsonify({
                'status': 'error',
                'message': 'Invalid credentials'
            }), 401
        
        # Generate token
        token = generate_jwt_token(user)
        
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'data': {
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'bio': user.get('bio', ''),
                    'avatar_id': user.get('heygen_avatar_id')
                },
                'token': token
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Login failed'
        }), 500

# Add API key test endpoint
@app.route('/api/avatar/test-api', methods=['GET'])
@token_required
def test_heygen_api(current_user):
    """Test HeyGen API connectivity and available features"""
    try:
        if not Config.HEYGEN_API_KEY:
            return jsonify({
                'status': 'error',
                'message': 'HeyGen API key not configured'
            }), 400

        headers = {
            "X-Api-Key": Config.HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        # Test 1: Basic connectivity
        response = requests.get(
            "https://api.heygen.com/v2/avatars",
            headers=headers,
            timeout=15
        )
        
        result = {
            'api_key_valid': response.status_code == 200,
            'status_code': response.status_code,
            'available_avatars': 0,
            'can_create_custom': False,
            'plan_type': 'unknown'
        }
        
        if response.status_code == 200:
            try:
                data = response.json()
                avatars = data.get("data", {}).get("avatars", [])
                result['available_avatars'] = len(avatars)
                result['sample_avatars'] = [
                    {
                        'id': avatar.get('avatar_id'),
                        'name': avatar.get('name', 'Unknown'),
                        'gender': avatar.get('gender', 'Unknown')
                    }
                    for avatar in avatars[:5]  # First 5 avatars
                ]
            except:
                pass
        
        # Test 2: Check quota
        try:
            quota_response = requests.get(
                "https://api.heygen.com/v1/user/remaining_quota",
                headers=headers,
                timeout=10
            )
            if quota_response.status_code == 200:
                quota_data = quota_response.json()
                result['remaining_quota'] = quota_data.get('data', {}).get('remaining_quota')
        except:
            pass
        
        return jsonify({
            'status': 'success',
            'data': result
        })
        
    except Exception as e:
        logger.error(f"API test error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'API test failed: {str(e)}'
        }), 500

# Avatar Management Routes
@app.route('/api/avatar/create', methods=['POST'])
@token_required
def create_avatar(current_user):
    """Create avatar from uploaded image"""
    try:
        # Get uploaded file
        image_file = request.files.get('file') or request.files.get('image')
        
        if not image_file:
            return jsonify({
                'status': 'error',
                'message': 'No image file provided'
            }), 400
        
        # Validate file
        try:
            validate_file_upload(image_file)
        except ValueError as ve:
            return jsonify({
                'status': 'error',
                'message': str(ve)
            }), 400
        
        logger.info(f"Creating avatar for user: {current_user['username']}")
        
        # Create talking photo avatar from uploaded image
        avatar_result = HeyGenAPI.create_photo_avatar(image_file)
        
        # CRITICAL FIX: Extract talking_photo_id correctly
        if avatar_result and avatar_result.get('avatar_id'):
            avatar_id = avatar_result['avatar_id']
            
            # Update user record with avatar info
            success = db.update_avatar_status(
                current_user['id'],
                {
                    'heygen_avatar_id': avatar_id,
                    'avatar_training_status': avatar_result.get('status', 'ready'),
                    'avatar_type': avatar_result.get('type', 'talking_photo')
                }
            )
            
            if success:
                logger.info(f"✅ Avatar created successfully: {avatar_id}")
                
                return jsonify({
                    'status': 'success',
                    'message': 'Custom avatar created from your photo!',
                    'data': {
                        'avatar_id': avatar_id,
                        'status': avatar_result.get('status', 'ready'),
                        'type': avatar_result.get('type', 'talking_photo'),
                        'is_custom': avatar_result.get('type') == 'talking_photo'
                    }
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to save avatar to database'
                }), 500
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to create avatar - no avatar ID returned'
            }), 500
            
    except Exception as e:
        logger.error(f"Avatar creation failed: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Avatar creation failed: {str(e)}'
        }), 500

@app.route('/api/avatar/status/<avatar_id>', methods=['GET'])
@token_required
def get_avatar_status(current_user, avatar_id):
    """Check avatar processing status - updated for 2025 API"""
    try:
        headers = {
            "X-Api-Key": Config.HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        # Try different endpoints to check avatar status
        endpoints_to_try = [
            f"https://api.heygen.com/v2/photo_avatar/{avatar_id}",
            f"https://api.heygen.com/v2/photo_avatar/avatar_group/{avatar_id}"
        ]
        
        for endpoint in endpoints_to_try:
            try:
                response = requests.get(endpoint, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    result = response.json()
                    
                    if not result.get('error'):
                        data = result.get('data', {})
                        status = data.get('status', 'ready')
                        
                        return jsonify({
                            'status': 'success',
                            'data': {
                                'exists': True,
                                'status': status,
                                'ready': status in ['completed', 'ready', 'success']
                            }
                        })
            except Exception as e:
                logger.warning(f"Endpoint {endpoint} failed: {e}")
                continue
        
        # Check if it's a regular avatar
        response = requests.get("https://api.heygen.com/v2/avatars", headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            avatars = data.get("data", {}).get("avatars", [])
            
            avatar_exists = any(avatar.get("avatar_id") == avatar_id for avatar in avatars)
            
            return jsonify({
                'status': 'success',
                'data': {
                    'exists': avatar_exists,
                    'status': 'ready' if avatar_exists else 'not_found',
                    'ready': avatar_exists
                }
            })
        
        return jsonify({
            'status': 'success',
            'data': {
                'exists': False,
                'status': 'not_found',
                'ready': False
            }
        })
        
    except Exception as e:
        logger.error(f"Avatar status check error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to check avatar status'
        }), 500

@app.route('/api/voice/save', methods=['POST'])
@token_required
def save_voice_preference(current_user):
    """FIXED: Save user's selected voice preference with proper persistence"""
    try:
        data = request.get_json()
        voice_id = data.get('voice_id')
        
        if not voice_id:
            return jsonify({
                'status': 'error',
                'message': 'Voice ID is required'
            }), 400
        
        logger.info(f"Saving voice preference for user {current_user['username']}: {voice_id}")
        
        # CRITICAL FIX: Update user's voice preference in database
        success = db.update_influencer(current_user['id'], {
            'preferred_voice_id': voice_id,
            'voice_updated_at': datetime.now(timezone.utc).isoformat()
        })
        
        if success:
            logger.info(f"Voice preference saved successfully: {voice_id}")
            
            # CRITICAL FIX: Also update the current user session data
            updated_user = db.get_influencer(current_user['id'])
            if updated_user:
                # Update the user data that gets returned by token_required
                current_user['preferred_voice_id'] = voice_id
            
            return jsonify({
                'status': 'success',
                'message': 'Voice preference saved successfully',
                'data': {
                    'voice_id': voice_id,
                    'voice_name': get_voice_name_by_id(voice_id),
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to save voice preference'
            }), 500
            
    except Exception as e:
        logger.error(f"Save voice preference error: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    
# Chat Routes
@app.route('/api/chat', methods=['POST'])
def chat():
    """FIXED: Handle chat messages and generate responses with proper voice persistence"""
    try:
        data = request.get_json()
        
        user_message = data.get('message', '').strip()
        influencer_username = data.get('influencer_username', '').strip()
        session_id = data.get('session_id', str(uuid.uuid4()))
        
        if not user_message or not influencer_username:
            return jsonify({
                'status': 'error',
                'message': 'Message and influencer username are required'
            }), 400
        
        logger.info(f"Processing chat message for {influencer_username}: {user_message}")
        
        # Get influencer
        influencer = db.get_influencer_by_username(influencer_username)
        if not influencer:
            return jsonify({
                'status': 'error',
                'message': 'Influencer not found'
            }), 404
        
        # CRITICAL FIX: Get user's preferred voice with proper fallback
        preferred_voice_id = influencer.get('preferred_voice_id') 
        if not preferred_voice_id:
            # Try alternative field names that might be used
            preferred_voice_id = (influencer.get('voice_id') or 
                                influencer.get('default_voice_id') or 
                                '2d5b0e6cf36f460aa7fc47e3eee4ba54')  # Default fallback
        
        logger.info(f"Using voice ID: {preferred_voice_id} for {influencer_username}")
        
        # Generate response with user's preferred voice
        try:
            response = chatbot.get_response(
                user_message,
                influencer['id'],
                session_id=session_id,
                influencer_name=influencer['username'],
                voice_mode=True,
                voice_id=preferred_voice_id  # CRITICAL: Pass the voice ID
            )
        except Exception as bot_error:
            logger.error(f"Chatbot error: {bot_error}")
            return jsonify({
                'status': 'error',
                'message': 'Failed to generate response'
            }), 500
        
        # Log interaction
        try:
            db.log_chat_interaction(
                influencer['id'],
                user_message,
                response['text'],
                response.get('has_product_recommendations', False),
                session_id
            )
        except Exception as log_error:
            logger.warning(f"Failed to log interaction: {log_error}")
        
        # Get voice name for response
        voice_name = get_voice_name_by_id(preferred_voice_id)
        
        return jsonify({
            'status': 'success',
            'data': {
                'text': response['text'],
                'video_url': response.get('video_url', ''),
                'audio_url': response.get('audio_url', ''),
                'has_product_recommendations': response.get('has_product_recommendations', False),
                'session_id': session_id,
                'voice_id': preferred_voice_id,
                'voice_name': voice_name,
                'using_custom_voice': bool(preferred_voice_id and preferred_voice_id != '2d5b0e6cf36f460aa7fc47e3eee4ba54')
            }
        })
        
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Chat service temporarily unavailable'
        }), 500

@app.route('/api/chat/<username>', methods=['GET'])
def get_chat_info(username):
    """Get public chat page information - ENHANCED WITH VOICE INFO"""
    try:
        logger.info(f"Getting chat info for username: {username}")
        
        influencer = db.get_influencer_by_username(username)
        
        if not influencer:
            logger.warning(f"Influencer '{username}' not found")
            return jsonify({
                'status': 'error',
                'message': 'Influencer not found'
            }), 404
        
        # Get voice information
        preferred_voice_id = influencer.get('preferred_voice_id', '2d5b0e6cf36f460aa7fc47e3eee4ba54')
        voice_name = get_voice_name_by_id(preferred_voice_id)
        
        logger.info(f"Chat info for {username}: avatar={bool(influencer.get('heygen_avatar_id'))}, voice={voice_name}")
        
        return jsonify({
            'status': 'success',
            'data': {
                'username': influencer['username'],
                'bio': influencer.get('bio', ''),
                'avatar_ready': bool(influencer.get('heygen_avatar_id')),
                'has_avatar': bool(influencer.get('heygen_avatar_id')),
                'chat_enabled': True,
                'voice_id': preferred_voice_id,
                'voice_name': voice_name,
                'avatar_id': influencer.get('heygen_avatar_id')
            }
        })
        
    except Exception as e:
        logger.error(f"Get chat info error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get chat information'
        }), 500

# FIXED EMBED GENERATE ENDPOINT for main.py

@app.route('/api/embed/generate', methods=['POST'])
@token_required
def generate_embed_code(current_user):
    """FIXED: Generate embed code for chatbot widget with proper URL generation"""
    try:
        data = request.get_json()
        
        # Get configuration with defaults
        config = {
            'width': data.get('width', '400px'),
            'height': data.get('height', '600px'),
            'position': data.get('position', 'bottom-right'),
            'theme': data.get('theme', 'default'),
            'trigger_text': data.get('trigger_text', 'Chat with me!'),
            'auto_open': data.get('auto_open', False),
            'custom_css': data.get('custom_css', '')
        }
        
        # CRITICAL FIX: Generate proper URLs
        base_url = request.url_root.rstrip('/')  # Remove trailing slash
        username = current_user['username']
        
        # Generate chat URL with proper encoding
        chat_url = f"{base_url}/chat.html?username={username}"
        
        # Generate widget ID
        widget_id = f"ac-widget-{int(datetime.now().timestamp())}"
        
        # Parse position for CSS
        position_parts = config['position'].split('-')
        v_pos = position_parts[0] if len(position_parts) > 0 else 'bottom'
        h_pos = position_parts[1] if len(position_parts) > 1 else 'right'
        
        # Generate position CSS
        position_css = ""
        if v_pos == 'top':
            position_css += "top: 20px; "
        else:
            position_css += "bottom: 20px; "
            
        if h_pos == 'left':
            position_css += "left: 20px; "
        else:
            position_css += "right: 20px; "
        
        # FIXED: Generate complete embed code
        embed_code = f"""<!-- AvatarCommerce Chatbot Widget -->
<div id="{widget_id}" class="ac-chatbot-widget" style="
    position: fixed;
    {position_css}
    z-index: 9999;
    width: {config['width']};
    height: {config['height']};
    {'' if config['auto_open'] else 'display: none;'}
">
    <!-- Trigger Button -->
    <button id="{widget_id}-trigger" class="ac-widget-trigger" style="
        position: absolute;
        bottom: -50px;
        right: 0;
        background: linear-gradient(135deg, #5e60ce, #7c3aed);
        color: white;
        border: none;
        padding: 12px 20px;
        border-radius: 25px;
        cursor: pointer;
        font-weight: 600;
        box-shadow: 0 4px 12px rgba(94, 96, 206, 0.3);
        transition: all 0.3s ease;
        {'' if not config['auto_open'] else 'display: none;'}
    " onclick="toggleWidget{widget_id}()">
        {config['trigger_text']}
    </button>
    
    <!-- Chat Widget -->
    <div class="ac-widget-container" style="
        width: 100%;
        height: 100%;
        border-radius: 15px;
        overflow: hidden;
        box-shadow: 0 8px 40px rgba(0,0,0,0.15);
        background: white;
        position: relative;
    ">
        <!-- Close Button -->
        <button onclick="closeWidget{widget_id}()" style="
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(255,255,255,0.9);
            border: none;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            cursor: pointer;
            z-index: 10;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
            color: #666;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        ">×</button>
        
        <!-- Chat Frame -->
        <iframe 
            src="{chat_url}&embed=true"
            width="100%"
            height="100%"
            frameborder="0"
            allow="microphone; camera"
            style="border: none;"
            title="AI Chat Assistant">
        </iframe>
    </div>
</div>

<script>
// Widget control functions
function toggleWidget{widget_id}() {{
    var widget = document.getElementById('{widget_id}');
    var trigger = document.getElementById('{widget_id}-trigger');
    if (widget && trigger) {{
        widget.style.display = 'block';
        trigger.style.display = 'none';
    }}
}}

function closeWidget{widget_id}() {{
    var widget = document.getElementById('{widget_id}');
    var trigger = document.getElementById('{widget_id}-trigger');
    if (widget && trigger) {{
        widget.style.display = 'none';
        trigger.style.display = 'block';
    }}
}}

// Auto-open functionality
{f'''
setTimeout(function() {{
    toggleWidget{widget_id}();
}}, 3000);
''' if config['auto_open'] else ''}

// Add hover effects and animations
document.addEventListener('DOMContentLoaded', function() {{
    var trigger = document.getElementById('{widget_id}-trigger');
    if (trigger) {{
        trigger.addEventListener('mouseenter', function() {{
            this.style.transform = 'translateY(-2px) scale(1.05)';
            this.style.boxShadow = '0 6px 20px rgba(94, 96, 206, 0.4)';
        }});
        trigger.addEventListener('mouseleave', function() {{
            this.style.transform = 'translateY(0) scale(1)';
            this.style.boxShadow = '0 4px 12px rgba(94, 96, 206, 0.3)';
        }});
    }}
    
    // Add pulse animation to trigger
    var style = document.createElement('style');
    style.textContent = `
        @keyframes ac-pulse {{
            0% {{ box-shadow: 0 4px 12px rgba(94, 96, 206, 0.3); }}
            50% {{ box-shadow: 0 4px 20px rgba(94, 96, 206, 0.5); }}
            100% {{ box-shadow: 0 4px 12px rgba(94, 96, 206, 0.3); }}
        }}
        .ac-widget-trigger {{
            animation: ac-pulse 2s infinite;
        }}
    `;
    document.head.appendChild(style);
}});
</script>

{f'<style>{config["custom_css"]}</style>' if config.get('custom_css') else ''}
<!-- End AvatarCommerce Widget -->"""

        # Generate preview and direct URLs
        preview_url = f"{base_url}/embed-preview.html?username={username}"
        direct_chat_url = chat_url
        
        # Save configuration to database (optional)
        try:
            if hasattr(db, 'save_embed_configuration'):
                db.save_embed_configuration(current_user['id'], config)
        except Exception as e:
            logger.warning(f"Could not save embed config: {e}")
        
        logger.info(f"Generated embed code for {username}")
        
        return jsonify({
            'status': 'success',
            'message': 'Embed code generated successfully',
            'data': {
                'embed_code': embed_code,
                'preview_url': preview_url,
                'chat_url': direct_chat_url,
                'widget_id': widget_id,
                'config': config
            }
        })
        
    except Exception as e:
        logger.error(f"Generate embed error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to generate embed code: {str(e)}'
        }), 500


@app.route('/api/embed/preview/<username>', methods=['GET'])
def embed_preview(username):
    """Generate embed preview page"""
    try:
        # Validate username
        influencer = db.get_influencer_by_username(username)
        if not influencer:
            return jsonify({
                'status': 'error',
                'message': 'Influencer not found'
            }), 404
        
        # Generate base URL
        base_url = request.url_root.rstrip('/')
        chat_url = f"{base_url}/chat.html?username={username}&embed=true"
        
        # Generate sample embed configuration
        sample_config = {
            'width': '400px',
            'height': '600px',
            'position': 'bottom-right',
            'theme': 'default',
            'trigger_text': f'Chat with {username}!',
            'auto_open': False,
            'custom_css': ''
        }
        
        # Generate preview HTML
        preview_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Embed Preview - {username}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 40px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: white;
        }}
        .preview-container {{
            max-width: 800px;
            margin: 0 auto;
            text-align: center;
        }}
        .preview-header {{
            margin-bottom: 40px;
        }}
        .preview-title {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        .preview-subtitle {{
            font-size: 1.2rem;
            opacity: 0.9;
        }}
        .demo-content {{
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 40px;
        }}
        .demo-text {{
            font-size: 1.1rem;
            line-height: 1.6;
            margin-bottom: 20px;
        }}
        .footer {{
            text-align: center;
            opacity: 0.8;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="preview-container">
        <div class="preview-header">
            <h1 class="preview-title">Embed Preview</h1>
            <p class="preview-subtitle">This is how the chat widget will appear on your website</p>
        </div>
        
        <div class="demo-content">
            <p class="demo-text">
                This is a sample webpage showing how the chatbot widget integrates seamlessly into any website. 
                The widget appears in the bottom-right corner and allows visitors to chat with {username}'s AI avatar.
            </p>
            <p class="demo-text">
                Visitors can click the chat button to open an interactive conversation with the AI avatar, 
                which can provide personalized recommendations and answer questions.
            </p>
        </div>
        
        <div class="footer">
            <p>Powered by AvatarCommerce | This is a preview of the embedded chat widget</p>
        </div>
    </div>
    
    <!-- Embedded Chat Widget -->
    <div id="ac-widget-preview" class="ac-chatbot-widget" style="
        position: fixed;
        bottom: 20px;
        right: 20px;
        z-index: 9999;
        width: 400px;
        height: 600px;
        display: none;
    ">
        <button id="ac-widget-trigger" class="ac-widget-trigger" style="
            position: absolute;
            bottom: -50px;
            right: 0;
            background: linear-gradient(135deg, #5e60ce, #7c3aed);
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 25px;
            cursor: pointer;
            font-weight: 600;
            box-shadow: 0 4px 12px rgba(94, 96, 206, 0.3);
            transition: all 0.3s ease;
        " onclick="togglePreviewWidget()">
            {sample_config['trigger_text']}
        </button>
        
        <div class="ac-widget-container" style="
            width: 100%;
            height: 100%;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 8px 40px rgba(0,0,0,0.15);
            background: white;
            position: relative;
        ">
            <button onclick="closePreviewWidget()" style="
                position: absolute;
                top: 10px;
                right: 10px;
                background: rgba(255,255,255,0.9);
                border: none;
                width: 30px;
                height: 30px;
                border-radius: 50%;
                cursor: pointer;
                z-index: 10;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 16px;
                color: #666;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            ">×</button>
            
            <iframe 
                src="{chat_url}"
                width="100%"
                height="100%"
                frameborder="0"
                allow="microphone; camera"
                style="border: none;"
                title="AI Chat Assistant Preview">
            </iframe>
        </div>
    </div>
    
    <script>
        function togglePreviewWidget() {{
            var widget = document.getElementById('ac-widget-preview');
            var trigger = document.getElementById('ac-widget-trigger');
            if (widget && trigger) {{
                widget.style.display = 'block';
                trigger.style.display = 'none';
            }}
        }}
        
        function closePreviewWidget() {{
            var widget = document.getElementById('ac-widget-preview');
            var trigger = document.getElementById('ac-widget-trigger');
            if (widget && trigger) {{
                widget.style.display = 'none';
                trigger.style.display = 'block';
            }}
        }}
        
        // Show trigger button after page loads
        document.addEventListener('DOMContentLoaded', function() {{
            document.getElementById('ac-widget-trigger').style.display = 'block';
            
            // Add hover effects
            var trigger = document.getElementById('ac-widget-trigger');
            if (trigger) {{
                trigger.addEventListener('mouseenter', function() {{
                    this.style.transform = 'translateY(-2px) scale(1.05)';
                    this.style.boxShadow = '0 6px 20px rgba(94, 96, 206, 0.4)';
                }});
                trigger.addEventListener('mouseleave', function() {{
                    this.style.transform = 'translateY(0) scale(1)';
                    this.style.boxShadow = '0 4px 12px rgba(94, 96, 206, 0.3)';
                }});
            }}
        }});
    </script>
</body>
</html>"""
        
        # Return HTML response
        response = make_response(preview_html)
        response.headers['Content-Type'] = 'text/html'
        return response
        
    except Exception as e:
        logger.error(f"Embed preview error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to generate preview'
        }), 500

# Helper function to get voice name by ID
def get_voice_name_by_id(voice_id):
    """Get voice name by voice ID - updated for real voices"""
    # Try to get from HeyGen API first
    try:
        headers = {
            "X-Api-Key": Config.HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        response = requests.get(
            "https://api.heygen.com/v1/voice/list",
            headers=headers,
            timeout=5
        )
        
        if response.status_code == 200:
            result = response.json()
            voices = result.get('data', {}).get('voices', [])
            
            for voice in voices:
                if voice.get('voice_id') == voice_id:
                    return voice.get('display_name', voice.get('name', 'Unknown Voice'))
    except:
        pass
    
    # Fallback to known working voices
    voice_map = {
        "2d5b0e6cf36f460aa7fc47e3eee4ba54": "Rachel (Professional)",
        "d7bbcdd6964c47bdaae26decade4a933": "David (Professional)",
    }
    return voice_map.get(voice_id, "Default Voice")

# Affiliate Management Routes
@app.route('/api/affiliate', methods=['POST'])
@token_required
def add_affiliate_link(current_user):
    """Add or update affiliate information"""
    try:
        data = request.get_json()
        
        platform = data.get('platform', '').strip()
        affiliate_id = data.get('affiliate_id', '').strip()
        
        if not platform or not affiliate_id:
            return jsonify({
                'status': 'error',
                'message': 'Platform and affiliate ID are required'
            }), 400
        
        # Add affiliate link
        try:
            link_data = db.add_affiliate_link(
                current_user['id'],
                platform,
                affiliate_id,
                data.get('is_primary', False)
            )
        except AttributeError:
            # Fallback if method doesn't exist
            link_data = {
                'id': str(uuid.uuid4()),
                'platform': platform,
                'affiliate_id': affiliate_id,
                'is_primary': data.get('is_primary', False)
            }
        
        return jsonify({
            'status': 'success',
            'message': 'Affiliate link added successfully',
            'data': link_data
        })
        
    except Exception as e:
        logger.error(f"Add affiliate link error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to add affiliate link'
        }), 500

@app.route('/api/affiliate', methods=['GET'])
@token_required
def get_affiliate_links(current_user):
    """Get all affiliate links for current user"""
    try:
        try:
            links = db.get_affiliate_links(current_user['id'])
        except AttributeError:
            # Fallback if method doesn't exist
            links = []
        
        return jsonify({
            'status': 'success',
            'data': {
                'affiliate_links': links
            }
        })
        
    except Exception as e:
        logger.error(f"Get affiliate links error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get affiliate links'
        }), 500

# Analytics Routes
@app.route('/api/analytics/dashboard', methods=['GET'])
@token_required
def get_dashboard_analytics(current_user):
    """Get dashboard analytics"""
    try:
        try:
            analytics = db.get_dashboard_analytics(current_user['id'])
        except AttributeError:
            # Fallback if method doesn't exist
            analytics = {
                'total_chats': 0,
                'unique_visitors': 0,
                'avatar_ready': bool(current_user.get('heygen_avatar_id')),
                'affiliate_links_count': 0
            }
        
        return jsonify({
            'status': 'success',
            'data': analytics
        })
        
    except Exception as e:
        logger.error(f"Analytics error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get analytics'
        }), 500

# Profile Routes
@app.route('/api/influencer/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    """FIXED: Get influencer profile with complete voice information"""
    try:
        # CRITICAL FIX: Get fresh data from database
        fresh_user_data = db.get_influencer(current_user['id'])
        
        if not fresh_user_data:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        # Get current voice preference with proper fallback
        preferred_voice_id = (fresh_user_data.get('preferred_voice_id') or 
                            fresh_user_data.get('voice_id') or
                            '2d5b0e6cf36f460aa7fc47e3eee4ba54')
        
        return jsonify({
            'status': 'success',
            'data': {
                'id': fresh_user_data['id'],
                'username': fresh_user_data['username'],
                'email': fresh_user_data['email'],
                'bio': fresh_user_data.get('bio', ''),
                'avatar_id': fresh_user_data.get('heygen_avatar_id'),
                'voice_id': fresh_user_data.get('voice_id'),
                'preferred_voice_id': preferred_voice_id,
                'voice_name': get_voice_name_by_id(preferred_voice_id),
                'created_at': fresh_user_data.get('created_at')
            }
        })
    except Exception as e:
        logger.error(f"Get profile error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get profile'
        }), 500

@app.route('/api/influencer/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    """Update influencer profile"""
    try:
        data = request.get_json()
        
        # Update allowed fields
        update_data = {}
        if 'bio' in data:
            update_data['bio'] = data['bio']
        if 'voice_id' in data:
            update_data['voice_id'] = data['voice_id']
        
        if update_data:
            success = db.update_influencer(current_user['id'], update_data)
            if success:
                return jsonify({
                    'status': 'success',
                    'message': 'Profile updated successfully'
                })
        
        return jsonify({
            'status': 'error',
            'message': 'Failed to update profile'
        }), 500
        
    except Exception as e:
        logger.error(f"Update profile error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to update profile'
        }), 500

# Voice Management Routes
@app.route('/api/avatar/list-voices', methods=['GET'])
def list_voices():
    """Get available voices from HeyGen API with 10 voice options"""
    try:
        headers = {
            "X-Api-Key": Config.HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        # Try multiple endpoints to get voices
        voice_endpoints = [
            "https://api.heygen.com/v1/voice/list",
            "https://api.heygen.com/v2/voices",
            "https://api.heygen.com/v1/voices"
        ]
        
        for endpoint in voice_endpoints:
            try:
                response = requests.get(endpoint, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    result = response.json()
                    voices_data = result.get('data', {})
                    
                    # Try different response structures
                    voices = (voices_data.get('voices') or 
                             voices_data.get('list') or 
                             result.get('voices', []))
                    
                    if voices and len(voices) > 0:
                        # Format voice data and get up to 10
                        formatted_voices = []
                        for voice in voices[:20]:  # Get more to filter
                            voice_id = voice.get("voice_id")
                            if voice_id and len(formatted_voices) < 10:
                                formatted_voices.append({
                                    "voice_id": voice_id,
                                    "name": voice.get("display_name", voice.get("name", f"Voice {len(formatted_voices)+1}")),
                                    "gender": voice.get("gender", "Unknown"),
                                    "language": voice.get("language", "English"),
                                    "style": voice.get("style", "Professional"),
                                    "preview_url": voice.get("preview_audio")
                                })
                        
                        if len(formatted_voices) >= 2:
                            return jsonify({
                                'status': 'success',
                                'data': {
                                    'voices': formatted_voices,
                                    'total_available': len(formatted_voices)
                                }
                            })
            except:
                continue
        
        # Enhanced fallback with more working voices
        fallback_voices = [
            {
                "voice_id": "2d5b0e6cf36f460aa7fc47e3eee4ba54",
                "name": "Rachel (Professional)",
                "gender": "Female",
                "language": "English",
                "style": "Professional",
                "preview_url": None
            },
            {
                "voice_id": "d7bbcdd6964c47bdaae26decade4a933", 
                "name": "David (Professional)",
                "gender": "Male",
                "language": "English",
                "style": "Professional",
                "preview_url": None
            },
            {
                "voice_id": "21m00Tcm4TlvDq8ikWAM",
                "name": "Rachel (Calm)",
                "gender": "Female",
                "language": "English",
                "style": "Calm",
                "preview_url": None
            },
            {
                "voice_id": "AZnzlk1XvdvUeBnXmlld",
                "name": "Domi (Strong)",
                "gender": "Female",
                "language": "English",
                "style": "Strong",
                "preview_url": None
            },
            {
                "voice_id": "EXAVITQu4vr4xnSDxMaL",
                "name": "Bella (Narration)",
                "gender": "Female",
                "language": "English",
                "style": "Narration",
                "preview_url": None
            },
            {
                "voice_id": "ErXwobaYiN019PkySvjV",
                "name": "Antoni (Well-rounded)",
                "gender": "Male",
                "language": "English",
                "style": "Well-rounded",
                "preview_url": None
            },
            {
                "voice_id": "VR6AewLTigWG4xSOukaG",
                "name": "Arnold (Crisp)",
                "gender": "Male",
                "language": "English",
                "style": "Crisp",
                "preview_url": None
            },
            {
                "voice_id": "pNInz6obpgDQGcFmaJgB",
                "name": "Adam (Deep)",
                "gender": "Male",
                "language": "English",
                "style": "Deep",
                "preview_url": None
            },
            {
                "voice_id": "yoZ06aMxZJJ28mfd3POQ",
                "name": "Sam (Raspy)",
                "gender": "Male",
                "language": "English",
                "style": "Raspy",
                "preview_url": None
            },
            {
                "voice_id": "29vD33N1CtxCmqQRPOHJ",
                "name": "Drew (Well-rounded)",
                "gender": "Male",
                "language": "English",
                "style": "Well-rounded",
                "preview_url": None
            }
        ]
        
        return jsonify({
            'status': 'success',
            'data': {
                'voices': fallback_voices,
                'total_available': len(fallback_voices)
            }
        })
        
    except Exception as e:
        logger.error(f"List voices error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get voices'
        }), 500

# Video Status Route
@app.route('/api/avatar/video-status/<video_id>', methods=['GET'])
@token_required
def check_video_status(current_user, video_id):
    """Check video generation status"""
    try:
        headers = {
            "X-Api-Key": Config.HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        response = requests.get(
            f"https://api.heygen.com/v1/video_status.get?video_id={video_id}",
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            video_info = result.get("data", {})
            
            return jsonify({
                'status': 'success',
                'data': {
                    'video_id': video_id,
                    'status': video_info.get('status', 'unknown'),
                    'video_url': video_info.get('video_url'),
                    'duration': video_info.get('duration'),
                    'error': video_info.get('error')
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to check video status'
            }), 500
            
    except Exception as e:
        logger.error(f"Video status check error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to check video status'
        }), 500

@app.route('/api/avatar/test-video', methods=['POST'])
@token_required
def test_avatar_video(current_user):
    """FIXED: Test avatar video generation with proper voice handling and persistence"""
    try:
        data = request.get_json()
        avatar_id = data.get('avatar_id')
        text = data.get('text', 'Hello! This is a test message.')
        voice_id = data.get('voice_id')
        
        if not avatar_id:
            return jsonify({
                'status': 'error',
                'message': 'Avatar ID is required'
            }), 400
        
        # CRITICAL FIX: If voice_id not provided, get from user's current preference
        if not voice_id:
            voice_id = current_user.get('preferred_voice_id', '2d5b0e6cf36f460aa7fc47e3eee4ba54')
        
        logger.info(f"Testing avatar video for {current_user['username']} with avatar {avatar_id} and voice {voice_id}")
        
        # CRITICAL FIX: Update user's voice preference IMMEDIATELY if changed
        current_voice = current_user.get('preferred_voice_id')
        if voice_id != current_voice:
            db.update_influencer(current_user['id'], {
                'preferred_voice_id': voice_id,
                'voice_updated_at': datetime.now(timezone.utc).isoformat()
            })
            logger.info(f"Updated voice preference to: {voice_id}")
            
            # Update current_user object for this request
            current_user['preferred_voice_id'] = voice_id
        
        # Generate video using chatbot with EXPLICIT voice parameter
        try:
            video_result = chatbot.generate_avatar_video_with_voice(text, current_user['id'], voice_id)
            
            if video_result:
                logger.info(f"Test video generated successfully: {video_result}")
                
                # Check if it's a direct URL or a video ID that needs polling
                if isinstance(video_result, str) and video_result.startswith('http'):
                    return jsonify({
                        'status': 'success',
                        'data': {
                            'video_url': video_result,
                            'voice_id': voice_id,
                            'voice_name': get_voice_name_by_id(voice_id)
                        }
                    })
                else:
                    return jsonify({
                        'status': 'success',
                        'data': {
                            'video_id': video_result,
                            'voice_id': voice_id,
                            'voice_name': get_voice_name_by_id(voice_id)
                        }
                    })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Video generation failed'
                }), 500
                
        except Exception as generation_error:
            logger.error(f"Video generation error: {generation_error}")
            return jsonify({
                'status': 'error',
                'message': f'Video generation failed: {str(generation_error)}'
            }), 500
            
    except Exception as e:
        logger.error(f"Test video error: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    
# Embed Configuration Routes
@app.route('/api/embed/config', methods=['GET'])
@token_required
def get_embed_config(current_user):
    """Get embed configuration"""
    try:
        try:
            config = db.get_embed_configuration(current_user['id'])
        except AttributeError:
            # Fallback if method doesn't exist
            config = None
            
        if not config:
            # Return default configuration
            config = {
                'width': '400px',
                'height': '600px',
                'position': 'bottom-right',
                'theme': 'default',
                'trigger_text': 'Chat with me!',
                'auto_open': False,
                'is_active': True
            }
        
        return jsonify({
            'status': 'success',
            'data': config
        })
        
    except Exception as e:
        logger.error(f"Get embed config error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get embed configuration'
        }), 500

@app.route('/api/embed/config', methods=['POST'])
@token_required
def save_embed_config(current_user):
    """Save embed configuration"""
    try:
        data = request.get_json()
        
        try:
            config = db.save_embed_configuration(current_user['id'], data)
        except AttributeError:
            # Fallback if method doesn't exist
            config = data
        
        return jsonify({
            'status': 'success',
            'message': 'Configuration saved successfully',
            'data': config
        })
        
    except Exception as e:
        logger.error(f"Save embed config error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to save configuration'
        }), 500

@app.route('/api/avatar/test-api-simple', methods=['GET'])
@token_required
def test_heygen_simple(current_user):
    """Simple HeyGen API connectivity test"""
    try:
        headers = {
            "Accept": "application/json",
            "X-Api-Key": Config.HEYGEN_API_KEY
        }
        
        # Test basic API connectivity
        response = requests.get(
            "https://api.heygen.com/v2/avatars",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            avatars = data.get("data", {}).get("avatars", [])
            
            return jsonify({
                'status': 'success',
                'message': 'HeyGen API is working!',
                'data': {
                    'api_working': True,
                    'available_avatars': len(avatars),
                    'sample_avatars': [
                        {
                            'id': avatar.get('avatar_id'),
                            'name': avatar.get('avatar_name')
                        }
                        for avatar in avatars[:3]  # First 3 avatars
                    ]
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'HeyGen API error: {response.status_code}',
                'data': {'api_working': False}
            }), 500
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'API test failed: {str(e)}',
            'data': {'api_working': False}
        }), 500

# =============================================================================
# APPLICATION STARTUP
# =============================================================================

def main():
    """Main application entry point"""
    logger.info("🚀 Starting AvatarCommerce API")
    
    # Create upload directory if it doesn't exist
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    
    # Get port from environment or use default
    port = int(os.getenv('PORT', 2000))
    
    # Run application
    logger.info(f"🌐 Server starting on port {port}")
    app.run(
        host='0.0.0.0',
        port=port,
        debug=os.getenv('FLASK_ENV') == 'development'
    )

if __name__ == '__main__':
    main()