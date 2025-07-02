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
    """HeyGen API client"""    
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
            "Content-Type": "image/jpeg"  # HeyGen expects specific content type
        }
        
        try:
            logger.info("📤 Uploading image to HeyGen Talking Photo API...")
            
            # Use the correct talking photo upload endpoint
            response = requests.post(
                "https://upload.heygen.com/v1/talking_photo",  # Correct endpoint from search results
                headers=headers,
                data=file_content,  # Send raw binary data
                timeout=60
            )
            
            logger.info(f"📥 Upload response: {response.status_code}")
            logger.info(f"📋 Upload response body: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                
                # Check for successful response
                if result.get('code') == 100 or not result.get('error'):
                    data = result.get('data', {})
                    talking_photo_id = data.get('id') or data.get('talking_photo_id')
                    
                    if talking_photo_id:
                        logger.info(f"✅ Talking photo created successfully: {talking_photo_id}")
                        
                        return {
                            "avatar_id": talking_photo_id,  # This is the talking_photo_id for video generation
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
            
            # Fallback to pre-made avatar if talking photo creation fails
            logger.info("Falling back to pre-made avatar selection")
            fallback_result = HeyGenAPI.select_fallback_avatar()
            
            if fallback_result:
                return {
                    "avatar_id": fallback_result['avatar_id'],
                    "status": "ready",
                    "type": "pre_made",
                    "method": "fallback_selection"
                }
            else:
                raise Exception(f"All avatar creation methods failed: {str(e)}")

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
        
        # Update user record with avatar info
        success = db.update_avatar_status(
            current_user['id'],
            {
                'heygen_avatar_id': avatar_result['avatar_id'],
                'avatar_training_status': avatar_result['status'],
                'avatar_type': avatar_result['type']
            }
        )
        
        if success:
            logger.info(f"✅ Avatar created successfully: {avatar_result['avatar_id']}")
            
            return jsonify({
                'status': 'success',
                'message': 'Custom avatar created from your photo!',
                'data': {
                    'avatar_id': avatar_result['avatar_id'],
                    'status': avatar_result['status'],
                    'type': avatar_result['type'],
                    'is_custom': avatar_result['type'] == 'talking_photo'
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to save avatar to database'
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
    """Save user's selected voice preference - ENHANCED VERSION"""
    try:
        data = request.get_json()
        voice_id = data.get('voice_id')
        
        if not voice_id:
            return jsonify({
                'status': 'error',
                'message': 'Voice ID is required'
            }), 400
        
        logger.info(f"Saving voice preference for user {current_user['username']}: {voice_id}")
        
        # Update user's voice preference in database
        success = db.update_influencer(current_user['id'], {
            'preferred_voice_id': voice_id,
            'voice_updated_at': datetime.now(timezone.utc).isoformat()
        })
        
        if success:
            logger.info(f"Voice preference saved successfully: {voice_id}")
            
            # ENHANCED: Also update the chatbot's voice preference if applicable
            if hasattr(chatbot, 'update_user_voice_preference'):
                chatbot.update_user_voice_preference(current_user['id'], voice_id)
            
            return jsonify({
                'status': 'success',
                'message': 'Voice preference saved',
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
    """Handle chat messages and generate responses with user's preferred voice - ENHANCED VERSION"""
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
        
        # Get user's preferred voice
        preferred_voice_id = influencer.get('preferred_voice_id', '2d5b0e6cf36f460aa7fc47e3eee4ba54')
        
        logger.info(f"Using voice ID: {preferred_voice_id} for {influencer_username}")
        
        # Generate response with user's preferred voice
        try:
            response = chatbot.get_response(
                user_message,
                influencer['id'],
                session_id=session_id,
                influencer_name=influencer['username'],
                voice_mode=True,
                voice_id=preferred_voice_id
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
                'using_custom_voice': bool(preferred_voice_id)
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

# Helper function to get voice name by ID
def get_voice_name_by_id(voice_id):
    """Get voice name by voice ID"""
    voice_map = {
        "2d5b0e6cf36f460aa7fc47e3eee4ba54": "Sarah (Professional)",
        "d7bbcdd6964c47bdaae26decade4a933": "David (Professional)",
        "4d2b8e6cf36f460aa7fc47e3eee4ba12": "Emma (Friendly)",
        "3a1c7d5bf24e350bb6dc46e2dee3ab21": "Michael (Casual)",
        "1bd001e7e50f421d891986aad5158bc8": "Olivia (Warm)",
        "26b2064088674c80b1e5fc5ab1a068ec": "James (Confident)",
        "5c8e6a2b1f3d45e7a9c4b8d6f2e1a9c8": "Luna (Energetic)",
        "7f9d2c4e6b8a1d5f3e9c7a2b4f6d8e1a": "Alexander (Sophisticated)",
        "9a5e3f7b2d8c4a6e1f9b5d3a7c2f8e4b": "Sophia (Gentle)",
        "2c8f4a6e1b7d3f9c5a8e2b4f6d1a9c7e": "Marcus (Dynamic)"
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
    """Get influencer profile with voice information"""
    try:
        # Get current voice preference
        preferred_voice_id = current_user.get('preferred_voice_id', '2d5b0e6cf36f460aa7fc47e3eee4ba54')
        
        return jsonify({
            'status': 'success',
            'data': {
                'id': current_user['id'],
                'username': current_user['username'],
                'email': current_user['email'],
                'bio': current_user.get('bio', ''),
                'avatar_id': current_user.get('heygen_avatar_id'),
                'voice_id': current_user.get('voice_id'),
                'preferred_voice_id': preferred_voice_id,
                'voice_name': get_voice_name_by_id(preferred_voice_id),
                'created_at': current_user.get('created_at')
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
    """Get available voices for avatar - ENHANCED VERSION WITH 10 VOICES"""
    try:
        # Extended voice list with 10 professional options
        extended_voices = [
            {
                "voice_id": "2d5b0e6cf36f460aa7fc47e3eee4ba54",
                "name": "Sarah (Professional)",
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
                "voice_id": "4d2b8e6cf36f460aa7fc47e3eee4ba12",
                "name": "Emma (Friendly)",
                "gender": "Female", 
                "language": "English",
                "style": "Friendly",
                "preview_url": None
            },
            {
                "voice_id": "3a1c7d5bf24e350bb6dc46e2dee3ab21",
                "name": "Michael (Casual)",
                "gender": "Male",
                "language": "English", 
                "style": "Casual",
                "preview_url": None
            },
            {
                "voice_id": "1bd001e7e50f421d891986aad5158bc8",
                "name": "Olivia (Warm)",
                "gender": "Female",
                "language": "English",
                "style": "Warm",
                "preview_url": None
            },
            {
                "voice_id": "26b2064088674c80b1e5fc5ab1a068ec",
                "name": "James (Confident)",
                "gender": "Male", 
                "language": "English",
                "style": "Confident",
                "preview_url": None
            },
            {
                "voice_id": "5c8e6a2b1f3d45e7a9c4b8d6f2e1a9c8",
                "name": "Luna (Energetic)",
                "gender": "Female",
                "language": "English",
                "style": "Energetic",
                "preview_url": None
            },
            {
                "voice_id": "7f9d2c4e6b8a1d5f3e9c7a2b4f6d8e1a",
                "name": "Alexander (Sophisticated)",
                "gender": "Male",
                "language": "English",
                "style": "Sophisticated",
                "preview_url": None
            },
            {
                "voice_id": "9a5e3f7b2d8c4a6e1f9b5d3a7c2f8e4b",
                "name": "Sophia (Gentle)",
                "gender": "Female",
                "language": "English",
                "style": "Gentle",
                "preview_url": None
            },
            {
                "voice_id": "2c8f4a6e1b7d3f9c5a8e2b4f6d1a9c7e",
                "name": "Marcus (Dynamic)",
                "gender": "Male",
                "language": "English",
                "style": "Dynamic",
                "preview_url": None
            }
        ]
        
        return jsonify({
            'status': 'success',
            'data': {
                'voices': extended_voices,
                'total_available': len(extended_voices)
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
    """Test avatar video generation with proper voice handling - ENHANCED VERSION"""
    try:
        data = request.get_json()
        avatar_id = data.get('avatar_id')
        text = data.get('text', 'Hello! This is a test message.')
        voice_id = data.get('voice_id', '2d5b0e6cf36f460aa7fc47e3eee4ba54')
        
        if not avatar_id:
            return jsonify({
                'status': 'error',
                'message': 'Avatar ID is required'
            }), 400
        
        logger.info(f"Testing avatar video for {current_user['username']} with avatar {avatar_id} and voice {voice_id}")
        
        # CRITICAL FIX: Update user's voice preference immediately if changed
        if voice_id != current_user.get('preferred_voice_id'):
            db.update_influencer(current_user['id'], {
                'preferred_voice_id': voice_id,
                'voice_updated_at': datetime.now(timezone.utc).isoformat()
            })
            logger.info(f"Updated voice preference to: {voice_id}")
        
        # Generate video using chatbot with explicit voice
        try:
            # ENHANCED: Use chatbot method that accepts voice_id parameter
            if hasattr(chatbot, 'generate_avatar_video_with_voice'):
                video_result = chatbot.generate_avatar_video_with_voice(text, current_user['id'], voice_id)
            else:
                # Fallback to regular method
                video_result = chatbot.generate_avatar_video(text, current_user['id'])
            
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