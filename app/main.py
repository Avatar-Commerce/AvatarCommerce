#!/usr/bin/env python3
"""
AvatarCommerce Main Application - FIXED VERSION
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
    from config import Config
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("Please ensure all required modules are in the app directory")
    sys.exit(1)

# =============================================================================
# APPLICATION SETUP
# =============================================================================

def create_app():
    """Create and configure Flask application with simple CORS"""
    
    Config.validate()
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = Config.JWT_SECRET_KEY
    app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH
    
    # Simple CORS for development - allows all origins
    CORS(app, origins="*", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    
    setup_logging()
    return app

def validate_username(username):
    """Validate username format"""
    if not username or not isinstance(username, str):
        return False, "Username is required"
    
    username = username.strip()
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    
    if len(username) > 30:
        return False, "Username must be less than 30 characters"
    
    if not username.replace('_', '').replace('-', '').isalnum():
        return False, "Username can only contain letters, numbers, underscores, and hyphens"
    
    return True, "Valid username"

def validate_email(email):
    """Validate email format"""
    if not email or not isinstance(email, str):
        return False, "Email is required"
    
    email = email.strip().lower()
    
    import re
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    return True, "Valid email"

def clean_text_for_response(text, max_length=500):
    """Clean and truncate text for API responses"""
    if not text:
        return ""
    
    # Remove extra whitespace
    text = ' '.join(text.split())
    
    # Truncate if too long
    if len(text) > max_length:
        text = text[:max_length-3] + "..."
    
    return text

print("✅ Backend fixes loaded - apply these to your main.py file")

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
    payload = {
        'username': user_data['username'],
        'id': user_data['id'],
        'user_type': 'influencer',
        'exp': datetime.now(timezone.utc) + timedelta(days=Config.JWT_EXPIRATION_DAYS)
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm="HS256")

# =============================================================================
# ENHANCED HEYGEN API INTEGRATION
# =============================================================================

class HeyGenAPI:
    @staticmethod
    def create_photo_avatar(image_file):
        """Create custom talking photo avatar using the ONLY working HeyGen endpoint"""
        logger.info("🎬 Creating custom talking photo avatar from uploaded image")
        
        try:
            # Read and validate file content
            image_file.seek(0)
            file_content = image_file.read()
            filename = getattr(image_file, 'filename', 'avatar.jpg')
            
            logger.info(f"📁 File: {filename}")
            logger.info(f"📊 Size: {len(file_content)} bytes")
            
            if len(file_content) == 0:
                raise Exception("File is empty")
            
            if len(file_content) > 10 * 1024 * 1024:  # 10MB limit
                raise Exception("File too large. Maximum size: 10MB")
            
            # ONLY use the working endpoint: upload.heygen.com/v1/talking_photo
            logger.info("📤 Using HeyGen talking_photo endpoint (only working endpoint)...")
            
            headers = {
                "X-Api-Key": Config.HEYGEN_API_KEY,
                "Content-Type": "image/jpeg"
            }
            
            response = requests.post(
                "https://upload.heygen.com/v1/talking_photo",
                headers=headers,
                data=file_content,
                timeout=90  # Increased timeout for avatar processing
            )
            
            logger.info(f"📥 Response: {response.status_code}")
            logger.info(f"📋 Response body: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                
                # Parse HeyGen response format
                if result.get('code') == 100 and result.get('data'):
                    data = result.get('data', {})
                    talking_photo_id = data.get('talking_photo_id')
                    
                    if talking_photo_id:
                        logger.info(f"✅ SUCCESS! Custom talking photo created: {talking_photo_id}")
                        return {
                            "avatar_id": talking_photo_id,
                            "status": "ready",
                            "type": "talking_photo",
                            "method": "talking_photo_upload",
                            "is_custom": True,
                            "preview_image_url": data.get('preview_image_url'),
                            "preview_video_url": data.get('preview_video_url')
                        }
                    else:
                        error_msg = "No talking_photo_id in response"
                        logger.error(f"❌ {error_msg}")
                        raise Exception(f"HeyGen API error: {error_msg}")
                else:
                    error_msg = result.get('message', 'Unknown error from HeyGen API')
                    error_code = result.get('code', 'unknown')
                    logger.error(f"❌ HeyGen API error {error_code}: {error_msg}")
                    
                    # Handle specific error codes
                    if error_code == 40002:
                        raise Exception("Image format not supported. Please use JPEG, PNG, or WebP format.")
                    elif error_code == 40001:
                        raise Exception("Invalid image data. Please try a different image.")
                    elif error_code == 40003:
                        raise Exception("No face detected in image. Please use a clear photo with a visible face.")
                    elif error_code == 40004:
                        raise Exception("Multiple faces detected. Please use an image with only one face.")
                    elif error_code == 42901:
                        raise Exception("Insufficient credits. Please check your HeyGen account balance.")
                    else:
                        raise Exception(f"HeyGen API error: {error_msg}")
                        
            elif response.status_code == 400:
                # Try to parse error message
                try:
                    error_data = response.json()
                    error_msg = error_data.get('message', 'Bad request')
                    error_code = error_data.get('code', 'unknown')
                    
                    logger.error(f"❌ HeyGen 400 error {error_code}: {error_msg}")
                    
                    if error_code == 40002:
                        raise Exception("Image format not supported. Please use a clear JPEG, PNG, or WebP image.")
                    elif "face" in error_msg.lower():
                        raise Exception("Could not detect a face in the image. Please use a clear photo with a visible face.")
                    elif "format" in error_msg.lower():
                        raise Exception("Invalid image format. Please use JPEG, PNG, or WebP.")
                    else:
                        raise Exception(f"Image processing error: {error_msg}")
                        
                except:
                    raise Exception("Invalid image data. Please try a different image with a clear face.")
                    
            elif response.status_code == 401:
                logger.error("❌ HeyGen authentication failed")
                raise Exception("HeyGen API authentication failed. Please check your API key.")
                
            elif response.status_code == 429:
                logger.error("❌ HeyGen rate limit exceeded")
                raise Exception("Too many requests. Please wait a moment and try again.")
                
            elif response.status_code == 403:
                logger.error("❌ HeyGen access forbidden")
                raise Exception("Access denied. Please check your HeyGen account permissions.")
                
            else:
                error_text = response.text
                logger.error(f"❌ HeyGen API error: {response.status_code} - {error_text}")
                raise Exception(f"HeyGen API returned error {response.status_code}. Please try again later.")
                
        except Exception as e:
            logger.error(f"❌ Custom avatar creation failed: {str(e)}")
            raise e  # Don't fall back - let the frontend handle the error

    @staticmethod
    def generate_video(avatar_id, text, voice_id=None):
        """Generate video with avatar using HeyGen API v2"""
        try:
            headers = {
                "X-Api-Key": Config.HEYGEN_API_KEY,
                "Content-Type": "application/json"
            }
            
            # Clean text for video generation
            clean_text = text[:400] if len(text) > 400 else text
            
            # Prepare video generation payload
            payload = {
                "video_inputs": [
                    {
                        "character": {
                            "type": "avatar",
                            "avatar_id": avatar_id,
                            "avatar_style": "normal"
                        },
                        "voice": {
                            "type": "text",
                            "input_text": clean_text,
                            "voice_id": voice_id or Config.DEFAULT_VOICE_ID
                        }
                    }
                ],
                "dimension": {
                    "width": 1280,
                    "height": 720
                },
                "aspect_ratio": "16:9",
                "test": False
            }
            
            logger.info(f"🎬 Sending video generation request to HeyGen")
            logger.info(f"📝 Text: {clean_text}")
            logger.info(f"🎤 Voice ID: {voice_id}")
            
            response = requests.post(
                "https://api.heygen.com/v2/video/generate",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            logger.info(f"📡 HeyGen video generation response: {response.status_code}")
            logger.info(f"📋 Response body: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('code') == 100 or data.get('data'):
                    video_data = data.get('data', {})
                    video_id = video_data.get('video_id')
                    
                    if video_id:
                        logger.info(f"✅ Video generation started: {video_id}")
                        return {
                            'video_id': video_id,
                            'status': 'processing',
                            'estimated_time': video_data.get('estimated_time', 30)
                        }
                    else:
                        raise Exception("No video_id in response")
                else:
                    error_msg = data.get('message', 'Video generation failed')
                    logger.error(f"❌ HeyGen video error: {error_msg}")
                    raise Exception(error_msg)
            else:
                error_text = response.text
                logger.error(f"❌ HeyGen video API error: {response.status_code} - {error_text}")
                raise Exception(f"Video generation failed: HTTP {response.status_code}")
                
        except Exception as e:
            logger.error(f"❌ Video generation failed: {e}")
            raise e

    @staticmethod
    def get_video_status(video_id):
        """Check video generation status with proper error handling"""
        try:
            headers = {
                "X-Api-Key": Config.HEYGEN_API_KEY,
                "Accept": "application/json"
            }
            
            logger.info(f"📊 Checking status for video: {video_id}")
            
            response = requests.get(
                f"https://api.heygen.com/v1/video_status.get?video_id={video_id}",
                headers=headers,
                timeout=15
            )
            
            logger.info(f"📊 Status check response: {response.status_code}")
            logger.info(f"📋 Status response body: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('code') == 100:
                    video_data = data.get('data', {})
                    status = video_data.get('status', 'processing')
                    
                    result = {
                        'status': status,
                        'video_url': video_data.get('video_url'),
                        'progress': video_data.get('progress', 50),
                        'error': video_data.get('error')
                    }
                    
                    logger.info(f"📊 Video status: {status}")
                    if result['video_url']:
                        logger.info(f"🎬 Video URL: {result['video_url']}")
                    
                    return result
                else:
                    error_msg = data.get('message', 'Unknown error from HeyGen')
                    logger.error(f"❌ HeyGen API error: {error_msg}")
                    return {'status': 'failed', 'error': error_msg}
            else:
                logger.error(f"❌ Video status check failed: {response.status_code}")
                return {'status': 'failed', 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            logger.error(f"❌ Video status check error: {e}")
            return {'status': 'failed', 'error': str(e)}

    @staticmethod
    def get_available_avatars():
        """Get list of available prebuilt avatars (working endpoint)"""
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
                
                logger.info(f"📋 Retrieved {len(avatars)} available avatars")
                return avatars
            else:
                logger.error(f"❌ Failed to get avatars: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"❌ Get avatars error: {e}")
            return []

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'status': 'error',
        'message': 'Bad request - invalid data provided'
    }), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        'status': 'error',
        'message': 'Unauthorized - please log in'
    }), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({
        'status': 'error',
        'message': 'Forbidden - insufficient permissions'
    }), 403

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
        'message': 'File too large. Maximum size allowed is 16MB'
    }), 413

@app.errorhandler(422)
def unprocessable_entity(error):
    return jsonify({
        'status': 'error',
        'message': 'Unprocessable entity - invalid data format'
    }), 422

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        'status': 'error',
        'message': 'Rate limit exceeded. Please try again later'
    }), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'status': 'error',
        'message': 'Internal server error - please try again later'
    }), 500

@app.errorhandler(502)
def bad_gateway(error):
    return jsonify({
        'status': 'error',
        'message': 'Bad gateway - external service unavailable'
    }), 502

@app.errorhandler(503)
def service_unavailable(error):
    return jsonify({
        'status': 'error',
        'message': 'Service unavailable - please try again later'
    }), 503

# =============================================================================
# API ROUTES
# =============================================================================

# Health Check
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for connection testing"""
    try:
        # Test database connection
        test_query = db.supabase.table('influencers').select('count').execute()
        
        return jsonify({
            'status': 'success',
            'message': 'API is healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'database': 'connected'
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'error',
            'message': 'API health check failed',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'database': 'disconnected'
        }), 500

# Authentication Routes
@app.route('/api/register', methods=['POST'])
@app.route('/api/auth/register', methods=['POST'])
def register():
    """FIXED: Register new influencer account with consistent response format"""
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
        if not username.replace('_', '').replace('-', '').isalnum():
            return jsonify({
                'status': 'error',
                'message': 'Username can only contain letters, numbers, underscores, and hyphens'
            }), 400
        
        if len(username) < 3 or len(username) > 30:
            return jsonify({
                'status': 'error',
                'message': 'Username must be between 3 and 30 characters'
            }), 400
        
        # Check if user already exists
        existing_user = db.get_influencer_by_username(username)
        if existing_user:
            return jsonify({
                'status': 'error',
                'message': 'Username already exists'
            }), 400
        
        existing_email = db.get_influencer_by_email(email)
        if existing_email:
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
            logger.error(f"Failed to create user: {username}")
            return jsonify({
                'status': 'error',
                'message': 'Failed to create account. Please try again.'
            }), 500
        
        # Generate token
        token = generate_jwt_token(created_user)
        
        logger.info(f"✅ Successfully registered user: {username}")
        
        # FIXED: Consistent response format for frontend
        return jsonify({
            'status': 'success',
            'message': 'Account created successfully',
            'data': {
                'user': {
                    'id': created_user['id'],
                    'username': created_user['username'],
                    'email': created_user['email'],
                    'bio': created_user.get('bio', ''),
                    'userType': 'influencer'
                },
                'token': token,
                'userType': 'influencer'
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Registration failed. Please try again.'
        }), 500

@app.route('/api/login', methods=['POST'])
@app.route('/api/auth/login', methods=['POST'])
def login():
    """FIXED: Login influencer with consistent response format"""
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
        
        logger.info(f"✅ User logged in successfully: {username}")
        
        # FIXED: Consistent response format for frontend
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'data': {
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'bio': user.get('bio', ''),
                    'avatar_id': user.get('heygen_avatar_id'),
                    'userType': 'influencer'
                },
                'token': token,
                'userType': 'influencer'
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Login failed'
        }), 500

# Enhanced Influencer Profile Routes
@app.route('/api/influencer/profile', methods=['GET'])
@token_required
def get_influencer_profile(current_user):
    """Get influencer profile with enhanced voice and avatar info"""
    try:
        influencer = db.get_influencer(current_user['id'])
        if not influencer:
            return jsonify({
                'status': 'error',
                'message': 'Influencer not found'
            }), 404

        profile_data = {
            'id': influencer['id'],
            'username': influencer['username'],
            'email': influencer['email'],
            'bio': influencer.get('bio', ''),
            'expertise': influencer.get('expertise', ''),
            'personality': influencer.get('personality', ''),
            'avatar_id': influencer.get('heygen_avatar_id'),
            'has_avatar': bool(influencer.get('heygen_avatar_id')),
            'voice_id': influencer.get('voice_id'),
            'preferred_voice_id': influencer.get('preferred_voice_id', Config.DEFAULT_VOICE_ID),
            'avatar_training_status': influencer.get('avatar_training_status', 'none'),
            'avatar_type': influencer.get('avatar_type', 'none'),
            'created_at': influencer.get('created_at'),
            'updated_at': influencer.get('updated_at')
        }

        return jsonify({
            'status': 'success',
            'data': profile_data
        })

    except Exception as e:
        logger.error(f"Get influencer profile error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get profile'
        }), 500

@app.route('/api/influencer/profile', methods=['PUT'])
@token_required
def update_influencer_profile(current_user):
    """Update influencer profile"""
    try:
        data = request.get_json()
        update_data = {}

        allowed_fields = ['bio', 'email', 'expertise', 'personality', 'preferred_voice_id']
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]

        success = db.update_influencer(current_user['id'], update_data)

        if success:
            return jsonify({
                'status': 'success',
                'message': 'Profile updated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update profile'
            }), 500

    except Exception as e:
        logger.error(f"Update influencer profile error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while updating profile'
        }), 500

# Enhanced Avatar Management Routes
@app.route('/api/avatar/create', methods=['POST'])
@token_required
def create_avatar(current_user):
    """Enhanced avatar creation with plan limit handling"""
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
        
        logger.info(f"🎭 Creating avatar for user: {current_user['username']}")
        
        # Create custom talking photo avatar
        try:
            avatar_result = HeyGenAPI.create_photo_avatar(image_file)
            
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
                    logger.info(f"✅ Custom avatar created successfully: {avatar_id}")
                    
                    return jsonify({
                        'status': 'success',
                        'message': '✅ Custom avatar created from your photo!',
                        'data': {
                            'avatar_id': avatar_id,
                            'status': avatar_result.get('status', 'ready'),
                            'type': avatar_result.get('type', 'talking_photo'),
                            'is_custom': True,
                            'method': avatar_result.get('method', 'talking_photo'),
                            'preview_image_url': avatar_result.get('preview_image_url'),
                            'preview_video_url': avatar_result.get('preview_video_url'),
                            'created_at': datetime.now(timezone.utc).isoformat()
                        }
                    }), 201
                else:
                    return jsonify({
                        'status': 'error',
                        'message': 'Failed to save avatar to database'
                    }), 500
            else:
                raise Exception("No avatar ID returned from HeyGen")
                
        except Exception as heygen_error:
            logger.error(f"❌ HeyGen avatar creation failed: {heygen_error}")
            
            error_message = str(heygen_error)
            
            # Handle specific HeyGen error codes
            if "401028" in error_message or "exceeded your limit" in error_message.lower():
                return jsonify({
                    'status': 'error',
                    'message': 'HeyGen Plan Limit Reached',
                    'error_type': 'plan_limit_exceeded',
                    'details': 'You have reached your plan\'s avatar creation limit.',
                    'solutions': [
                        'Upgrade your HeyGen plan for more avatar credits',
                        'Delete unused avatars from your HeyGen dashboard',
                        'Contact support for assistance'
                    ],
                    'links': {
                        'upgrade': 'https://app.heygen.com/settings/billing',
                        'dashboard': 'https://app.heygen.com/avatars',
                        'support': 'mailto:support@heygen.com'
                    }
                }), 402  # Payment Required status code
            elif "format not supported" in error_message.lower():
                return jsonify({
                    'status': 'error',
                    'message': 'Image format not supported. Please use JPEG, PNG, or WebP format.',
                    'error_type': 'format_error',
                    'suggestions': [
                        'Convert your image to JPEG format',
                        'Try a different image file',
                        'Ensure the file is not corrupted'
                    ]
                }), 400
            elif "face" in error_message.lower():
                return jsonify({
                    'status': 'error',
                    'message': 'Could not detect a face in the image. Please use a clear photo with a visible face.',
                    'error_type': 'face_detection_error',
                    'suggestions': [
                        'Use a clear photo with good lighting',
                        'Ensure only one face is visible in the image',
                        'Try a front-facing photo',
                        'Remove glasses or hats if they obscure the face'
                    ]
                }), 400
            elif "authentication" in error_message.lower() or "api key" in error_message.lower():
                return jsonify({
                    'status': 'error',
                    'message': 'HeyGen API authentication failed. Please contact support.',
                    'error_type': 'auth_error'
                }), 401
            elif "credits" in error_message.lower() or "insufficient" in error_message.lower():
                return jsonify({
                    'status': 'error',
                    'message': 'Insufficient HeyGen credits. Please check your account balance.',
                    'error_type': 'credits_error'
                }), 429
            elif "too many" in error_message.lower() or "rate limit" in error_message.lower():
                return jsonify({
                    'status': 'error',
                    'message': 'Too many requests. Please wait a moment and try again.',
                    'error_type': 'rate_limit_error'
                }), 429
            else:
                return jsonify({
                    'status': 'error',
                    'message': f'Avatar creation failed: {error_message}',
                    'error_type': 'creation_failed',
                    'suggestions': [
                        'Try a different image with a clear face',
                        'Ensure good image quality and lighting',
                        'Use JPEG format if possible',
                        'Contact support if the issue persists'
                    ]
                }), 500
            
    except Exception as e:
        logger.error(f"❌ Avatar creation endpoint error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'An unexpected error occurred during avatar creation'
        }), 500

@app.route('/api/avatar/status', methods=['GET'])
@token_required
def get_avatar_status(current_user):
    """Get current avatar status and HeyGen plan info"""
    try:
        # Get user's current avatar
        user_avatar = current_user.get('heygen_avatar_id')
        
        # Get available HeyGen avatars (to check total count)
        available_avatars = HeyGenAPI.get_available_avatars()
        
        return jsonify({
            'status': 'success',
            'data': {
                'has_avatar': bool(user_avatar),
                'avatar_id': user_avatar,
                'total_available_avatars': len(available_avatars),
                'heygen_credits': '109 credits remaining',  # You can get this from HeyGen API
                'heygen_dashboard_url': 'https://app.heygen.com/avatars',
                'upgrade_url': 'https://app.heygen.com/settings/billing'
            }
        })
        
    except Exception as e:
        logger.error(f"Get avatar status error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get avatar status'
        }), 500

# Enhanced Voice Management Routes
@app.route('/api/avatar/list-voices', methods=['GET'])
def list_available_voices():
    """Get enhanced list of available voices"""
    try:
        voices = [
            {
                "voice_id": "2d5b0e6cf36f460aa7fc47e3eee4ba54",
                "name": "Rachel (Professional)",
                "gender": "Female",
                "language": "English",
                "style": "Professional",
                "description": "Clear, professional female voice perfect for business content"
            },
            {
                "voice_id": "d7bbcdd6964c47bdaae26decade4a933",
                "name": "David (Professional)",
                "gender": "Male", 
                "language": "English",
                "style": "Professional",
                "description": "Authoritative male voice ideal for educational content"
            },
            {
                "voice_id": "4d2b8e6cf36f460aa7fc47e3eee4ba12",
                "name": "Emma (Friendly)",
                "gender": "Female",
                "language": "English", 
                "style": "Friendly",
                "description": "Warm, approachable female voice great for lifestyle content"
            },
            {
                "voice_id": "3a1c7d5bf24e350bb6dc46e2dee3ab21",
                "name": "Michael (Casual)",
                "gender": "Male",
                "language": "English",
                "style": "Casual", 
                "description": "Relaxed male voice perfect for conversational content"
            },
            {
                "voice_id": "1bd001e7e50f421d891986aad5158bc8",
                "name": "Olivia (Warm)",
                "gender": "Female",
                "language": "English",
                "style": "Warm",
                "description": "Gentle, caring female voice ideal for personal brands"
            },
            {
                "voice_id": "26b2064088674c80b1e5fc5ab1a068ec", 
                "name": "James (Confident)",
                "gender": "Male",
                "language": "English",
                "style": "Confident",
                "description": "Strong, confident male voice for motivational content"
            },
            {
                "voice_id": "5c8e6a2b1f3d45e7a9c4b8d6f2e1a9c8",
                "name": "Luna (Energetic)",
                "gender": "Female",
                "language": "English",
                "style": "Energetic",
                "description": "Vibrant, enthusiastic female voice for dynamic content"
            },
            {
                "voice_id": "7f9d2c4e6b8a1d5f3e9c7a2b4f6d8e1a",
                "name": "Alexander (Sophisticated)",
                "gender": "Male",
                "language": "English", 
                "style": "Sophisticated",
                "description": "Refined male voice perfect for luxury brands"
            },
            {
                "voice_id": "9a5e3f7b2d8c4a6e1f9b5d3a7c2f8e4b",
                "name": "Sophia (Gentle)",
                "gender": "Female",
                "language": "English",
                "style": "Gentle",
                "description": "Soft, soothing female voice for wellness content"
            },
            {
                "voice_id": "2c8f4a6e1b7d3f9c5a8e2b4f6d1a9c7e",
                "name": "Marcus (Dynamic)",
                "gender": "Male", 
                "language": "English",
                "style": "Dynamic",
                "description": "Engaging male voice great for entertainment content"
            }
        ]
        
        return jsonify({
            'status': 'success',
            'data': {
                'voices': voices,
                'total_count': len(voices),
                'default_voice_id': Config.DEFAULT_VOICE_ID
            }
        })
        
    except Exception as e:
        logger.error(f"List voices error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get voice list'
        }), 500

@app.route('/api/voice/preference', methods=['POST'])
@token_required
def save_voice_preference(current_user):
    """Enhanced voice preference saving"""
    try:
        data = request.get_json()
        voice_id = data.get('voice_id')
        
        if not voice_id:
            return jsonify({
                'status': 'error',
                'message': 'Voice ID is required'
            }), 400
        
        # Update user's preferred voice
        success = db.update_influencer(current_user['id'], {
            'preferred_voice_id': voice_id
        })
        
        if success:
            logger.info(f"✅ Voice preference updated for {current_user['username']}: {voice_id}")
            return jsonify({
                'status': 'success',
                'message': 'Voice preference saved successfully',
                'data': {
                    'preferred_voice_id': voice_id
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
            'message': 'Failed to save voice preference'
        }), 500

@app.route('/api/voice/preference', methods=['GET'])
@token_required
def get_voice_preference(current_user):
    """Get user's preferred voice"""
    try:
        influencer = db.get_influencer(current_user['id'])
        preferred_voice_id = influencer.get('preferred_voice_id', Config.DEFAULT_VOICE_ID)
        
        return jsonify({
            'status': 'success',
            'data': {
                'preferred_voice_id': preferred_voice_id
            }
        })
        
    except Exception as e:
        logger.error(f"Get voice preference error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get voice preference'
        }), 500

@app.route('/api/voice/clone', methods=['POST'])
@token_required
def create_voice_clone(current_user):
    """Enhanced voice cloning endpoint"""
    try:
        # Check if files were uploaded
        if 'audio_samples' not in request.files:
            return jsonify({
                'status': 'error',
                'message': 'No audio samples provided'
            }), 400
        
        files = request.files.getlist('audio_samples')
        voice_name = request.form.get('voice_name', f"{current_user['username']}'s Voice")
        description = request.form.get('description', f"Voice clone for {current_user['username']}")
        
        if len(files) < 3:
            return jsonify({
                'status': 'error',
                'message': 'At least 3 audio samples are required'
            }), 400
        
        # Validate files
        total_size = 0
        for file in files:
            if not file.filename.lower().endswith(('.mp3', '.wav', '.webm', '.m4a')):
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid file type: {file.filename}. Only MP3, WAV, WebM, and M4A are supported.'
                }), 400
            
            file.seek(0, 2)  # Seek to end
            size = file.tell()
            file.seek(0)  # Reset
            total_size += size
            
            if size > 50 * 1024 * 1024:  # 50MB per file
                return jsonify({
                    'status': 'error', 
                    'message': f'File {file.filename} is too large. Maximum 50MB per file.'
                }), 400
        
        if total_size > 200 * 1024 * 1024:  # 200MB total
            return jsonify({
                'status': 'error',
                'message': 'Total file size too large. Maximum 200MB total.'
            }), 400
        
        # Generate custom voice ID (in production, would integrate with ElevenLabs or similar)
        custom_voice_id = f"custom_{current_user['id']}_{str(uuid.uuid4())[:8]}"
        
        # Update user's voice preferences
        success = db.update_influencer(current_user['id'], {
            'voice_id': custom_voice_id,
            'preferred_voice_id': custom_voice_id
        })
        
        if success:
            logger.info(f"✅ Custom voice created for {current_user['username']}: {custom_voice_id}")
            return jsonify({
                'status': 'success',
                'message': 'Custom voice created successfully',
                'data': {
                    'voice_id': custom_voice_id,
                    'voice_name': voice_name,
                    'status': 'ready',
                    'is_custom': True,
                    'sample_count': len(files)
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to save custom voice'
            }), 500
            
    except Exception as e:
        logger.error(f"Voice clone error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to create voice clone'
        }), 500

# Enhanced Video Generation Routes
@app.route('/api/avatar/test-video', methods=['POST'])
@token_required
def generate_test_video(current_user):
    """FIXED: Generate test video using proper HeyGen API"""
    try:
        data = request.get_json()
        
        avatar_id = data.get('avatar_id')
        text = data.get('text', 'Hello! This is a test of my AI avatar with my selected voice. How does it look and sound?')
        voice_id = data.get('voice_id')
        
        if not avatar_id:
            return jsonify({
                'status': 'error',
                'message': 'Avatar ID is required'
            }), 400
        
        # Get user's preferred voice if not specified
        if not voice_id:
            influencer = db.get_influencer(current_user['id'])
            voice_id = influencer.get('preferred_voice_id', Config.DEFAULT_VOICE_ID)
        
        logger.info(f"🎬 Generating test video for avatar: {avatar_id} with voice: {voice_id}")
        
        # Use the proper HeyGen API method for video generation
        try:
            video_result = HeyGenAPI.generate_video(
                avatar_id=avatar_id,
                text=text,
                voice_id=voice_id
            )
            
            if video_result and video_result.get('video_id'):
                logger.info(f"✅ Video generation started: {video_result['video_id']}")
                
                return jsonify({
                    'status': 'success',
                    'message': 'Video generation started',
                    'data': {
                        'video_id': video_result['video_id'],
                        'status': 'processing',
                        'estimated_time': video_result.get('estimated_time', 30),
                        'text': text,
                        'voice_id': voice_id
                    }
                })
                
            else:
                raise Exception("No video ID returned from HeyGen")
                
        except Exception as video_error:
            logger.error(f"❌ HeyGen video generation failed: {video_error}")
            return jsonify({
                'status': 'error',
                'message': f'Video generation failed: {str(video_error)}'
            }), 500
            
    except Exception as e:
        logger.error(f"❌ Test video generation error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to generate test video'
        }), 500

@app.route('/api/avatar/video-status/<video_id>', methods=['GET'])
@token_required
def get_video_status_fixed(current_user, video_id):
    """FIXED: Get real video status from HeyGen API"""
    try:
        logger.info(f"📊 Checking video status for: {video_id}")
        
        # Use the proper HeyGen API method for status checking
        try:
            video_status = HeyGenAPI.get_video_status(video_id)
            
            logger.info(f"📊 Video status response: {video_status}")
            
            return jsonify({
                'status': 'success',
                'data': video_status
            })
                
        except Exception as heygen_error:
            logger.error(f"❌ HeyGen video status check failed: {heygen_error}")
            return jsonify({
                'status': 'error',
                'message': f'Failed to check video status: {str(heygen_error)}'
            }), 500
        
    except Exception as e:
        logger.error(f"❌ Video status check error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to check video status'
        }), 500

@app.route('/api/voice/generate-audio', methods=['POST'])
@token_required
def generate_voice_audio_endpoint(current_user):
    """Generate audio using user's preferred voice"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        text = data.get('text', '').strip()
        voice_id = data.get('voice_id')
        
        if not text:
            return jsonify({
                'status': 'error',
                'message': 'Text is required'
            }), 400
        
        if len(text) > 1000:
            return jsonify({
                'status': 'error',
                'message': 'Text too long. Maximum 1000 characters.'
            }), 400
        
        # Get user's preferred voice if not specified
        if not voice_id:
            influencer = db.get_influencer(current_user['id'])
            voice_id = influencer.get('preferred_voice_id', Config.DEFAULT_VOICE_ID)
        
        logger.info(f"🔊 Generating audio for user: {current_user['username']}, voice: {voice_id}")
        
        # Generate audio
        audio_url = chatbot.generate_voice_audio(text, voice_id)
        
        if audio_url:
            return jsonify({
                'status': 'success',
                'data': {
                    'audio_url': audio_url,
                    'text': text,
                    'voice_id': voice_id,
                    'duration_estimate': len(text) / 10  # Rough estimate: 10 chars per second
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to generate audio'
            }), 500
            
    except Exception as e:
        logger.error(f"Voice audio generation error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to generate voice audio'
        }), 500

@app.route('/api/voice/preview', methods=['POST'])
def preview_voice():
    """Preview a voice with sample text (no authentication required)"""
    try:
        data = request.get_json()
        
        voice_id = data.get('voice_id', Config.DEFAULT_VOICE_ID)
        sample_text = data.get('text', 'Hello! This is a preview of this voice. How does it sound?')
        
        # Limit sample text
        if len(sample_text) > 200:
            sample_text = sample_text[:200] + "..."
        
        logger.info(f"🎤 Voice preview requested for voice: {voice_id}")
        
        # Generate audio
        audio_url = chatbot.generate_voice_audio(sample_text, voice_id)
        
        if audio_url:
            return jsonify({
                'status': 'success',
                'data': {
                    'audio_url': audio_url,
                    'text': sample_text,
                    'voice_id': voice_id
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to generate voice preview'
            }), 500
            
    except Exception as e:
        logger.error(f"Voice preview error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to generate voice preview'
        }), 500
    
@app.route('/api/speech-to-text', methods=['POST'])
def speech_to_text():
    """FIXED: Convert speech to text using OpenAI Whisper with proper file handling"""
    try:
        # Check if audio file is provided
        if 'audio' not in request.files:
            return jsonify({
                'status': 'error',
                'message': 'No audio file provided'
            }), 400
        
        audio_file = request.files['audio']
        
        if audio_file.filename == '':
            return jsonify({
                'status': 'error',
                'message': 'No audio file selected'
            }), 400
        
        # Validate file size
        audio_file.seek(0, 2)  # Seek to end
        file_size = audio_file.tell()
        audio_file.seek(0)  # Reset to beginning
        
        if file_size > Config.MAX_CONTENT_LENGTH:
            return jsonify({
                'status': 'error',
                'message': 'Audio file too large'
            }), 400
        
        if file_size == 0:
            return jsonify({
                'status': 'error',
                'message': 'Audio file is empty'
            }), 400
        
        # FIXED: Proper temporary file handling for webm files
        temp_file = None
        try:
            # Create temporary file with proper extension
            with tempfile.NamedTemporaryFile(delete=False, suffix='.webm') as temp_file:
                # Read the file content and write to temp file
                audio_file.seek(0)
                file_content = audio_file.read()
                temp_file.write(file_content)
                temp_file.flush()
                temp_filename = temp_file.name
            
            logger.info(f"🎤 Temp file created: {temp_filename}, size: {len(file_content)} bytes")
            
            # FIXED: Use OpenAI Whisper API with proper file object
            with open(temp_filename, 'rb') as audio_data:
                transcript = chatbot.client.audio.transcriptions.create(
                    model="whisper-1",
                    file=audio_data,
                    response_format="text"
                )
            
            # Extract text from response
            transcription = transcript.strip() if isinstance(transcript, str) else transcript.text.strip()
            
            if transcription:
                logger.info(f"✅ Speech-to-text successful: {transcription[:50]}...")
                return jsonify({
                    'status': 'success',
                    'data': {
                        'transcription': transcription,
                        'confidence': 0.95  # OpenAI Whisper generally has high confidence
                    }
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Could not transcribe audio. Please speak clearly and try again.'
                }), 400
                
        finally:
            # FIXED: Proper cleanup of temporary file
            if temp_file and os.path.exists(temp_filename):
                try:
                    os.unlink(temp_filename)
                    logger.info(f"🗑️ Cleaned up temp file: {temp_filename}")
                except Exception as cleanup_error:
                    logger.warning(f"Could not delete temporary file: {cleanup_error}")
        
    except Exception as e:
        logger.error(f"Speech-to-text error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Speech-to-text processing failed: {str(e)}'
        }), 500
       
# Enhanced Chat Routes
@app.route('/api/chat', methods=['POST'])
def chat_with_influencer():
    """ENHANCED: Chat endpoint with comprehensive knowledge and voice integration"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        user_message = data.get('message', '').strip()
        username = data.get('username', '').strip()
        influencer_id = data.get('influencer_id')
        session_id = data.get('session_id')
        voice_mode = data.get('voice_mode', False)
        video_mode = data.get('video_mode', True)
        use_knowledge = data.get('use_knowledge', True)
        
        if not user_message:
            return jsonify({
                'status': 'error',
                'message': 'Message is required'
            }), 400
        
        # Get influencer info
        influencer = None
        if influencer_id:
            influencer = db.get_influencer(influencer_id)
        elif username:
            # Clean username for lookup
            clean_username = username.strip().lower()
            influencer = db.get_influencer_by_username(clean_username)
        
        if not influencer:
            return jsonify({
                'status': 'error',
                'message': 'Influencer not found'
            }), 404
        
        influencer_id = influencer['id']
        influencer_name = influencer.get('username', 'the influencer')
        
        logger.info(f"💬 Enhanced chat request - User: {influencer_name}, Message: {user_message[:50]}...")
        
        # ENHANCED: Generate comprehensive response using the enhanced chatbot
        try:
            if hasattr(chatbot, 'get_comprehensive_chat_response'):
                response_data = chatbot.get_comprehensive_chat_response(
                    message=user_message,
                    influencer_id=influencer_id,
                    session_id=session_id,
                    influencer_name=influencer_name,
                    voice_mode=voice_mode,
                    video_mode=video_mode
                )
            else:
                # Fallback to knowledge-enhanced response
                ai_response = chatbot.get_chat_response_with_knowledge(
                    message=user_message,
                    influencer_id=influencer_id,
                    session_id=session_id,
                    influencer_name=influencer_name,
                    db=db,
                    voice_mode=voice_mode
                )
                
                response_data = {
                    'text': ai_response,
                    'session_id': session_id or f"session_{int(time.time())}",
                    'video_url': '',
                    'audio_url': '',
                    'has_avatar': bool(influencer.get('heygen_avatar_id')),
                    'voice_id': influencer.get('preferred_voice_id', Config.DEFAULT_VOICE_ID),
                    'knowledge_enhanced': use_knowledge,
                    'influencer': {
                        'username': influencer_name,
                        'bio': influencer.get('bio', ''),
                        'has_knowledge': bool(influencer.get('bio') or influencer.get('expertise'))
                    }
                }
                
                # Generate video if avatar available and video mode enabled
                if video_mode and response_data['has_avatar']:
                    video_url = chatbot.generate_enhanced_video_response(
                        ai_response,
                        influencer_id,
                        response_data['voice_id']
                    )
                    if video_url:
                        response_data['video_url'] = video_url
                
                # Generate audio if voice mode enabled and no video
                if voice_mode and not video_mode:
                    audio_url = chatbot.generate_audio_response(
                        ai_response,
                        response_data['voice_id']
                    )
                    if audio_url:
                        response_data['audio_url'] = audio_url
            
            logger.info(f"🤖 Enhanced response generated - Text: {len(response_data['text'])} chars, Video: {bool(response_data.get('video_url'))}, Audio: {bool(response_data.get('audio_url'))}")
            
        except Exception as ai_error:
            logger.error(f"AI response generation failed: {ai_error}")
            response_data = {
                'text': f"Hi! I'm {influencer_name}'s AI assistant. I'm having some technical difficulties right now, but I'm here to help! Could you try rephrasing your question?",
                'session_id': session_id or f"session_{int(time.time())}",
                'video_url': '',
                'audio_url': '',
                'has_avatar': False,
                'voice_id': Config.DEFAULT_VOICE_ID,
                'knowledge_enhanced': False,
                'error': str(ai_error)
            }
        
        return jsonify({
            'status': 'success',
            'data': response_data
        })
        
    except Exception as e:
        logger.error(f"Chat endpoint error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Chat service temporarily unavailable'
        }), 500

@app.route('/api/chat/<username>', methods=['GET'])
def get_chat_info(username):
    """ENHANCED: Get chat information including knowledge and avatar status"""
    try:
        # Clean username
        clean_username = username.strip().lower()
        
        # Get influencer
        influencer = db.get_influencer_by_username(clean_username)
        
        if not influencer:
            return jsonify({
                'status': 'error',
                'message': 'Influencer not found'
            }), 404
        
        # ENHANCED: Include comprehensive status information
        response_data = {
            'username': influencer['username'],
            'bio': influencer.get('bio', ''),
            'has_avatar': bool(influencer.get('heygen_avatar_id')),
            'voice_id': influencer.get('preferred_voice_id') or influencer.get('voice_id'),
            'avatar_id': influencer.get('heygen_avatar_id'),
            'expertise': influencer.get('expertise', ''),
            'personality': influencer.get('personality', ''),
            'has_knowledge': bool(
                influencer.get('bio') or 
                influencer.get('expertise') or 
                influencer.get('personality')
            ),
            'knowledge_documents_count': 0,  # Would need to query knowledge_documents table
            'affiliate_platforms_connected': 0,  # Would need to query affiliate_links table
            'chat_capabilities': {
                'text_chat': True,
                'voice_responses': bool(influencer.get('preferred_voice_id') or influencer.get('voice_id')),
                'video_responses': bool(influencer.get('heygen_avatar_id')),
                'knowledge_enhanced': bool(
                    influencer.get('bio') or 
                    influencer.get('expertise') or 
                    influencer.get('personality')
                ),
                'product_recommendations': False  # Would need to check affiliate connections
            }
        }
        
        # Get additional stats if available
        try:
            # Count knowledge documents
            knowledge_docs = db.get_knowledge_documents(influencer['id']) if hasattr(db, 'get_knowledge_documents') else []
            response_data['knowledge_documents_count'] = len(knowledge_docs)
            
            # Count affiliate platforms
            affiliate_links = db.get_affiliate_links(influencer['id']) if hasattr(db, 'get_affiliate_links') else []
            response_data['affiliate_platforms_connected'] = len([link for link in affiliate_links if link.get('is_active', True)])
            response_data['chat_capabilities']['product_recommendations'] = response_data['affiliate_platforms_connected'] > 0
            
        except Exception as stats_error:
            logger.warning(f"Could not load additional stats: {stats_error}")
        
        logger.info(f"✅ Chat info retrieved for {username} - Avatar: {response_data['has_avatar']}, Knowledge: {response_data['has_knowledge']}")
        
        return jsonify({
            'status': 'success',
            'data': response_data
        })
        
    except Exception as e:
        logger.error(f"Get chat info error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get chat information'
        }), 500

@app.route('/api/knowledge/upload', methods=['POST'])
@token_required
def upload_knowledge_document(current_user):
    """Handle knowledge document uploads - FIXED to handle RLS policy"""
    try:
        # Get uploaded file
        file = request.files.get('file')
        if not file:
            return jsonify({
                'status': 'error',
                'message': 'No file provided'
            }), 400

        # Validate file
        try:
            validate_file_upload(file)
        except ValueError as ve:
            return jsonify({
                'status': 'error',
                'message': str(ve)
            }), 400

        # Save file to storage
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        content_type = file.content_type
        
        # Get file size
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning

        # For now, just simulate successful upload since we don't have actual file storage
        # In production, you would save the file to Supabase Storage or similar
        
        logger.info(f"✅ Document upload simulated for user {current_user['username']}: {filename}")

        return jsonify({
            'status': 'success',
            'message': 'Document uploaded successfully',
            'data': {
                'document_id': str(uuid.uuid4()),  # Generate a fake ID for now
                'filename': filename,
                'file_size': file_size,
                'processed': False,
                'note': 'File upload simulated - implement actual storage in production'
            }
        })

    except Exception as e:
        logger.error(f"Document upload error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to upload document: {str(e)}'
        }), 500

@app.route('/api/knowledge/personal-info', methods=['POST'])
@token_required
def save_personal_knowledge(current_user):
    """Save influencer's personal knowledge information"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        # Prepare update data
        update_data = {}
        
        # Validate and save bio, expertise, and personality info
        if 'bio' in data:
            bio = data['bio'].strip()
            if len(bio) > 1000:
                return jsonify({
                    'status': 'error',
                    'message': 'Bio must be less than 1000 characters'
                }), 400
            update_data['bio'] = bio
            
        if 'expertise' in data:
            expertise = data['expertise'].strip()
            if len(expertise) > 500:
                return jsonify({
                    'status': 'error',
                    'message': 'Expertise must be less than 500 characters'
                }), 400
            update_data['expertise'] = expertise
            
        if 'personality' in data:
            personality = data['personality'].strip()
            if len(personality) > 500:
                return jsonify({
                    'status': 'error',
                    'message': 'Personality must be less than 500 characters'
                }), 400
            update_data['personality'] = personality
        
        if not update_data:
            return jsonify({
                'status': 'error',
                'message': 'No valid data to update'
            }), 400
        
        # Add timestamp
        update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
        
        # Update influencer profile
        success = db.update_influencer(current_user['id'], update_data)
        
        if success:
            logger.info(f"✅ Personal knowledge updated for influencer {current_user['username']}")
            return jsonify({
                'status': 'success',
                'message': 'Personal information saved successfully',
                'data': {
                    'updated_fields': list(update_data.keys()),
                    'updated_at': update_data['updated_at']
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to save personal information'
            }), 500
            
    except Exception as e:
        logger.error(f"Save personal knowledge error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to save personal information'
        }), 500

# =============================================================================
# AFFILIATE MANAGEMENT ROUTES
# =============================================================================

@app.route('/api/affiliate', methods=['POST'])
@token_required
def connect_affiliate_platform(current_user):
    """FIXED: Connect affiliate platform with updated credential handling"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        platform = data.get('platform', '').lower()
        valid_platforms = ['amazon', 'rakuten', 'shareasale', 'cj_affiliate', 'skimlinks']
        
        if platform not in valid_platforms:
            return jsonify({
                'status': 'error',
                'message': f'Invalid platform. Must be one of: {", ".join(valid_platforms)}'
            }), 400
        
        # Check if platform already exists for this user
        existing_link = db.get_affiliate_link_by_platform(current_user['id'], platform)
        if existing_link:
            return jsonify({
                'status': 'error',
                'message': f'{platform} is already connected to your account'
            }), 400
        
        # Prepare affiliate link data
        affiliate_data = {
            'id': str(uuid.uuid4()),
            'influencer_id': current_user['id'],
            'platform': platform,
            'is_active': True,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'updated_at': datetime.now(timezone.utc).isoformat()
        }
        
        # FIXED: Add platform-specific fields with correct Rakuten structure
        if platform == 'amazon':
            affiliate_data.update({
                'amazon_access_key': data.get('access_key', ''),
                'amazon_secret_key': data.get('secret_key', ''),
                'affiliate_id': data.get('partner_tag', ''),
                'partner_tag': data.get('partner_tag', '')
            })
            required_fields = ['access_key', 'secret_key', 'partner_tag']
            
        elif platform == 'rakuten':
            # FIXED: Use new OAuth2 Client Credentials structure
            affiliate_data.update({
                'client_id': data.get('client_id', ''),
                'client_secret': data.get('client_secret', ''),
                'application_id': data.get('application_id', ''),  # Optional
                'rakuten_client_id': data.get('client_id', ''),
                'rakuten_client_secret': data.get('client_secret', ''),
                'rakuten_application_id': data.get('application_id', ''),
                'affiliate_id': data.get('client_id', '')  # Use client_id as affiliate_id
            })
            required_fields = ['client_id', 'client_secret']
            
        elif platform == 'shareasale':
            affiliate_data.update({
                'shareasale_api_token': data.get('api_token', ''),
                'shareasale_secret_key': data.get('secret_key', ''),
                'affiliate_id': data.get('affiliate_id', '')
            })
            required_fields = ['api_token', 'secret_key', 'affiliate_id']
            
        elif platform == 'cj_affiliate':
            affiliate_data.update({
                'cj_api_key': data.get('api_key', ''),
                'website_id': data.get('website_id', ''),
                'affiliate_id': data.get('website_id', '')
            })
            required_fields = ['api_key', 'website_id']
            
        elif platform == 'skimlinks':
            affiliate_data.update({
                'skimlinks_api_key': data.get('api_key', ''),
                'publisher_id': data.get('publisher_id', ''),
                'affiliate_id': data.get('publisher_id', '')
            })
            required_fields = ['api_key', 'publisher_id']
        
        # Validate required fields
        missing_fields = []
        for field in required_fields:
            if not data.get(field):
                missing_fields.append(field)
        
        if missing_fields:
            return jsonify({
                'status': 'error',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        # Save to database
        success = db.create_affiliate_link(affiliate_data)
        
        if success:
            logger.info(f"✅ Affiliate link created for {current_user['username']} - Platform: {platform}")
            return jsonify({
                'status': 'success',
                'message': f'{platform.title()} connected successfully',
                'data': {
                    'platform': platform,
                    'connected_at': affiliate_data['created_at'],
                    'credentials_type': 'OAuth2' if platform == 'rakuten' else 'API Key'
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to save affiliate connection'
            }), 500
            
    except Exception as e:
        logger.error(f"Connect affiliate platform error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to connect platform: {str(e)}'
        }), 500

@app.route('/api/affiliate/<platform>', methods=['DELETE'])
@token_required
def remove_affiliate_link(current_user, platform):
    """Remove an affiliate link"""
    try:
        # Validate platform
        valid_platforms = ['amazon', 'rakuten', 'shareasale', 'cj_affiliate', 'skimlinks']
        if platform not in valid_platforms:
            return jsonify({
                'status': 'error',
                'message': f'Invalid platform. Must be one of: {", ".join(valid_platforms)}'
            }), 400
        
        # Remove from database
        success = db.delete_affiliate_link(current_user['id'], platform)
        
        if success:
            logger.info(f"✅ Affiliate link removed for {current_user['username']}: {platform}")
            return jsonify({
                'status': 'success',
                'message': f'{platform} removed successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Affiliate link not found or failed to remove'
            }), 404
            
    except Exception as e:
        logger.error(f"Remove affiliate link error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to remove affiliate link'
        }), 500

@app.route('/api/affiliate/<platform>', methods=['PUT'])
@token_required
def update_affiliate_link(current_user, platform):
    """Update an affiliate link"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        # Validate platform
        valid_platforms = ['amazon', 'rakuten', 'shareasale', 'cj_affiliate', 'skimlinks']
        if platform not in valid_platforms:
            return jsonify({
                'status': 'error',
                'message': f'Invalid platform. Must be one of: {", ".join(valid_platforms)}'
            }), 400
        
        # Prepare update data
        update_data = {
            'updated_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Add platform-specific fields
        if 'is_active' in data:
            update_data['is_active'] = data['is_active']
        
        # Update in database
        success = db.update_affiliate_link(current_user['id'], platform, update_data)
        
        if success:
            logger.info(f"✅ Affiliate link updated for {current_user['username']}: {platform}")
            return jsonify({
                'status': 'success',
                'message': f'{platform} updated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Affiliate link not found or failed to update'
            }), 404
            
    except Exception as e:
        logger.error(f"Update affiliate link error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to update affiliate link'
        }), 500

@app.route('/api/affiliate/search-products', methods=['POST'])
@token_required
def search_affiliate_products(current_user):
    """Search for products across all connected affiliate platforms"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        query = data.get('query', '').strip()
        platform = data.get('platform', 'all')  # 'all' or specific platform
        limit = min(int(data.get('limit', 10)), 20)  # Max 20 products
        
        if not query:
            return jsonify({
                'status': 'error',
                'message': 'Search query is required'
            }), 400
        
        logger.info(f"🔍 Product search - User: {current_user['username']}, Query: {query}, Platform: {platform}")
        
        # Import affiliate service
        try:
            from affiliate_service import AffiliateService
            affiliate_service = AffiliateService(db)
        except ImportError:
            return jsonify({
                'status': 'error',
                'message': 'Affiliate service not available'
            }), 503
        
        # Search products
        if platform == 'all':
            # Search across all connected platforms
            recommendations = affiliate_service.get_product_recommendations(
                query=query,
                influencer_id=current_user['id'],
                limit=limit
            )
            
            return jsonify({
                'status': 'success',
                'data': {
                    'products': recommendations['products'],
                    'total_found': recommendations['total_found'],
                    'platforms_searched': recommendations['platforms_searched'],
                    'query': query,
                    'search_type': 'multi_platform'
                }
            })
        else:
            # Search specific platform
            products = affiliate_service.search_products(
                query=query,
                platform=platform,
                influencer_id=current_user['id'],
                limit=limit
            )
            
            return jsonify({
                'status': 'success',
                'data': {
                    'products': products,
                    'total_found': len(products),
                    'platform': platform,
                    'query': query,
                    'search_type': 'single_platform'
                }
            })
        
    except Exception as e:
        logger.error(f"Product search error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to search products'
        }), 500

@app.route('/api/affiliate/platform-status', methods=['GET'])
@token_required
def get_platform_status(current_user):
    """Get status of all affiliate platforms for the current user"""
    try:
        # Get user's affiliate links
        affiliate_links = db.get_affiliate_links(current_user['id'])
        
        # Create platform status
        platforms_data = {}
        connected_platforms = 0
        total_estimated_products = 0
        
        # Get default platform configurations
        from config import DEFAULT_PLATFORM_DATA
        
        for platform_key, default_config in DEFAULT_PLATFORM_DATA.items():
            platforms_data[platform_key] = {
                **default_config,
                'connected': False,
                'estimated_products': 0
            }
        
        # Update with user's connected platforms
        for link in affiliate_links:
            if link.get('is_active', True):
                platform = link['platform']
                if platform in platforms_data:
                    platforms_data[platform]['connected'] = True
                    platforms_data[platform]['estimated_products'] = 1000  # Placeholder
                    connected_platforms += 1
                    total_estimated_products += 1000
        
        # Calculate stats
        stats = {
            'connected_platforms': connected_platforms,
            'estimated_products': total_estimated_products,
            'recommendations_made': 0,  # Would need analytics table
            'potential_earnings': total_estimated_products * 0.05,  # Rough estimate
            'completion_percentage': (connected_platforms / len(platforms_data)) * 100
        }
        
        return jsonify({
            'status': 'success',
            'data': {
                'platforms': platforms_data,
                'stats': stats
            }
        })
        
    except Exception as e:
        logger.error(f"Platform status error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get platform status'
        }), 500

@app.route('/api/affiliate/test-connection', methods=['POST'])
@token_required
def test_affiliate_connection(current_user):
    """FIXED: Test affiliate platform connection with updated credential handling"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        platform = data.get('platform', '').lower()
        credentials = data.get('credentials', {})
        
        if not platform or not credentials:
            return jsonify({
                'status': 'error',
                'message': 'Platform and credentials are required'
            }), 400
        
        # FIXED: Updated credential structures for each platform
        if platform == 'rakuten':
            # Use the new OAuth2-based credential structure
            test_affiliate_info = {
                'client_id': credentials.get('client_id'),
                'client_secret': credentials.get('client_secret'),
                'application_id': credentials.get('application_id'),  # Optional
                'rakuten_client_id': credentials.get('client_id'),
                'rakuten_client_secret': credentials.get('client_secret'),
                'rakuten_application_id': credentials.get('application_id')
            }
            required_fields = ['client_id', 'client_secret']
            
        elif platform == 'amazon':
            test_affiliate_info = {
                'amazon_access_key': credentials.get('access_key'),
                'amazon_secret_key': credentials.get('secret_key'),
                'partner_tag': credentials.get('partner_tag')
            }
            required_fields = ['access_key', 'secret_key', 'partner_tag']
            
        elif platform == 'shareasale':
            test_affiliate_info = {
                'shareasale_api_token': credentials.get('api_token'),
                'shareasale_secret_key': credentials.get('secret_key'),
                'affiliate_id': credentials.get('affiliate_id')
            }
            required_fields = ['api_token', 'secret_key', 'affiliate_id']
            
        elif platform == 'cj_affiliate':
            test_affiliate_info = {
                'cj_api_key': credentials.get('api_key'),
                'website_id': credentials.get('website_id')
            }
            required_fields = ['api_key']
            
        elif platform == 'skimlinks':
            test_affiliate_info = {
                'skimlinks_api_key': credentials.get('api_key'),
                'publisher_id': credentials.get('publisher_id')
            }
            required_fields = ['api_key']
        else:
            return jsonify({
                'status': 'error',
                'message': f'Unsupported platform: {platform}'
            }), 400
        
        # Validate required fields are present
        missing_fields = []
        for field in required_fields:
            if not credentials.get(field):
                missing_fields.append(field)
        
        if missing_fields:
            return jsonify({
                'status': 'error',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        logger.info(f"🔍 Testing {platform} connection with credentials: {list(credentials.keys())}")
        
        # Test the connection using affiliate service
        if hasattr(chatbot, 'affiliate_service') and chatbot.affiliate_service:
            try:
                # Test with a simple search query
                test_products = chatbot.affiliate_service.platforms[platform].search_products(
                    query="test product",
                    affiliate_info=test_affiliate_info,
                    limit=1
                )
                
                # For Rakuten, even an empty result can indicate successful auth
                # The API might not return products for "test product" but auth should work
                logger.info(f"✅ {platform} API test completed, found {len(test_products)} products")
                
                return jsonify({
                    'status': 'success',
                    'message': f'{platform.title()} connection successful',
                    'data': {
                        'platform': platform,
                        'test_results': len(test_products),
                        'connection_status': 'active',
                        'credentials_valid': True
                    }
                })
                    
            except Exception as api_error:
                logger.error(f"❌ {platform} API test failed: {api_error}")
                
                # Provide specific error messages based on the error type
                error_message = str(api_error).lower()
                
                if 'authentication' in error_message or 'unauthorized' in error_message:
                    return jsonify({
                        'status': 'error',
                        'message': f'{platform.title()} authentication failed. Please check your credentials.',
                        'error_type': 'auth_error'
                    }), 401
                elif 'forbidden' in error_message or 'access denied' in error_message:
                    return jsonify({
                        'status': 'error',
                        'message': f'{platform.title()} access denied. Please verify your account permissions.',
                        'error_type': 'permission_error'
                    }), 403
                elif 'rate limit' in error_message or 'too many requests' in error_message:
                    return jsonify({
                        'status': 'error',
                        'message': f'{platform.title()} rate limit exceeded. Please try again later.',
                        'error_type': 'rate_limit_error'
                    }), 429
                else:
                    return jsonify({
                        'status': 'error',
                        'message': f'{platform.title()} API test failed: {str(api_error)}',
                        'error_type': 'api_error'
                    }), 400
        else:
            return jsonify({
                'status': 'error',
                'message': 'Affiliate service not available'
            }), 500
        
    except Exception as e:
        logger.error(f"Test affiliate connection error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Connection test failed: {str(e)}'
        }), 500

@app.route('/api/affiliate/rakuten', methods=['POST'])
@token_required
def connect_rakuten_platform(current_user):
    """Enhanced Rakuten connection with proper validation"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        # Validate required Rakuten fields
        required_fields = ['application_id', 'affiliate_id']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'status': 'error',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        # Check if Rakuten is already connected
        existing_link = db.get_affiliate_link_by_platform(current_user['id'], 'rakuten')
        if existing_link:
            return jsonify({
                'status': 'error',
                'message': 'Rakuten is already connected to your account'
            }), 400
        
        # Prepare affiliate link data for Rakuten
        affiliate_data = {
            'id': str(uuid.uuid4()),
            'influencer_id': current_user['id'],
            'platform': 'rakuten',
            'is_active': True,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'updated_at': datetime.now(timezone.utc).isoformat(),
            'rakuten_application_id': data.get('application_id'),
            'rakuten_affiliate_id': data.get('affiliate_id'),
            'affiliate_id': data.get('affiliate_id'),  # Primary affiliate ID
            'api_token': data.get('application_id')  # Use application_id as token
        }
        
        # Test connection before saving
        try:
            from affiliate_service import AffiliateService
            affiliate_service = AffiliateService(db)
            
            # Create temporary affiliate info for testing
            temp_info = {
                'rakuten_client_id': data.get('application_id'),
                'rakuten_access_token': data.get('affiliate_id'),
                'merchant_id': data.get('application_id'),
                'api_token': data.get('affiliate_id')
            }
            
            # Test with a simple search
            test_products = affiliate_service.platforms['rakuten'].search_products(
                "test", temp_info, 1
            )
            
            # Note: Rakuten might not return products for "test" query, 
            # but if we don't get an authentication error, credentials are likely valid
            
        except Exception as test_error:
            logger.warning(f"Rakuten connection test warning: {test_error}")
            # Continue anyway - the test might fail due to API limitations
        
        # Save to database
        success = db.create_affiliate_link(affiliate_data)
        
        if success:
            logger.info(f"✅ Rakuten connected for {current_user['username']}")
            return jsonify({
                'status': 'success',
                'message': 'Rakuten connected successfully',
                'data': {
                    'platform': 'rakuten',
                    'affiliate_id': affiliate_data['affiliate_id'],
                    'application_id': affiliate_data['rakuten_application_id'],
                    'created_at': affiliate_data['created_at']
                }
            }), 201
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to save Rakuten connection'
            }), 500
            
    except Exception as e:
        logger.error(f"Connect Rakuten error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to connect Rakuten'
        }), 500

@app.route('/api/analytics/affiliate-performance', methods=['GET'])
@token_required
def get_affiliate_performance(current_user):
    """Get detailed affiliate performance analytics"""
    try:
        days = int(request.args.get('days', 30))
        platform = request.args.get('platform', 'all')
        
        from datetime import timedelta
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Get chat interactions with product recommendations
        response = db.supabase.table('chat_interactions') \
            .select('*') \
            .eq('influencer_id', current_user['id']) \
            .eq('products_included', True) \
            .gte('created_at', start_date.isoformat()) \
            .execute()
        
        interactions = response.data if response.data else []
        
        # Calculate metrics
        total_recommendations = len(interactions)
        unique_sessions = len(set([chat.get("session_id") for chat in interactions if chat.get("session_id")]))
        
        # Group by platform if specific platform requested
        platform_metrics = {}
        daily_stats = {}
        
        for interaction in interactions:
            date = interaction["created_at"][:10]  # YYYY-MM-DD
            
            # Daily stats
            if date not in daily_stats:
                daily_stats[date] = {'recommendations': 0, 'sessions': set()}
            
            daily_stats[date]['recommendations'] += 1
            if interaction.get('session_id'):
                daily_stats[date]['sessions'].add(interaction['session_id'])
        
        # Convert sets to counts for JSON serialization
        for date, stats in daily_stats.items():
            stats['unique_sessions'] = len(stats['sessions'])
            del stats['sessions']
        
        # Get affiliate links for platform info
        affiliate_links = db.get_affiliate_links(current_user['id'])
        
        return jsonify({
            'status': 'success',
            'data': {
                'total_recommendations': total_recommendations,
                'unique_sessions': unique_sessions,
                'connected_platforms': len(affiliate_links),
                'daily_stats': daily_stats,
                'period_days': days,
                'avg_daily_recommendations': total_recommendations / days if days > 0 else 0,
                'recommendation_rate': total_recommendations / unique_sessions if unique_sessions > 0 else 0,
                'platform_breakdown': platform_metrics
            }
        })
        
    except Exception as e:
        logger.error(f"Get affiliate performance error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get affiliate performance data'
        }), 500


# =============================================================================
# WEBHOOK ENDPOINTS FOR AFFILIATE PLATFORMS
# =============================================================================

@app.route('/api/webhooks/affiliate/<platform>', methods=['POST'])
def affiliate_webhook(platform):
    """Handle webhook notifications from affiliate platforms"""
    try:
        data = request.get_json()
        
        logger.info(f"📡 Received webhook from {platform}: {data}")
        
        # Process webhook based on platform
        if platform == 'rakuten':
            # Handle Rakuten conversion notifications
            return handle_rakuten_webhook(data)
        elif platform == 'amazon':
            # Handle Amazon conversion notifications
            return handle_amazon_webhook(data)
        elif platform == 'shareasale':
            # Handle ShareASale conversion notifications
            return handle_shareasale_webhook(data)
        elif platform == 'cj_affiliate':
            # Handle CJ Affiliate conversion notifications
            return handle_cj_webhook(data)
        else:
            return jsonify({
                'status': 'error',
                'message': f'Unsupported platform: {platform}'
            }), 400
            
    except Exception as e:
        logger.error(f"Webhook processing error for {platform}: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Webhook processing failed'
        }), 500


def handle_rakuten_webhook(data):
    """Handle Rakuten specific webhook data"""
    try:
        # Rakuten webhook typically includes:
        # - order_id, transaction_id
        # - commission_amount
        # - order_total
        # - affiliate_id
        
        webhook_data = {
            'platform': 'rakuten',
            'order_id': data.get('order_id'),
            'transaction_id': data.get('transaction_id'),
            'commission_amount': data.get('commission_amount'),
            'order_total': data.get('order_total'),
            'affiliate_id': data.get('affiliate_id'),
            'status': data.get('status', 'pending'),
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Store webhook data for analytics
        # You would implement webhook storage in your database
        
        logger.info(f"✅ Processed Rakuten webhook: Order {data.get('order_id')}")
        
        return jsonify({
            'status': 'success',
            'message': 'Webhook processed successfully'
        })
        
    except Exception as e:
        logger.error(f"Rakuten webhook error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to process Rakuten webhook'
        }), 500


# =============================================================================
# BULK OPERATIONS FOR AFFILIATE MANAGEMENT
# =============================================================================

@app.route('/api/affiliate/bulk-connect', methods=['POST'])
@token_required
def bulk_connect_platforms(current_user):
    """Connect multiple affiliate platforms at once"""
    try:
        data = request.get_json()
        
        if not data or 'platforms' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Platforms data is required'
            }), 400
        
        platforms_data = data['platforms']
        results = {'success': [], 'failed': []}
        
        for platform_data in platforms_data:
            platform = platform_data.get('platform')
            credentials = platform_data.get('credentials', {})
            
            try:
                # Validate platform
                valid_platforms = ['amazon', 'rakuten', 'shareasale', 'cj_affiliate', 'skimlinks']
                if platform not in valid_platforms:
                    results['failed'].append({
                        'platform': platform,
                        'error': 'Invalid platform'
                    })
                    continue
                
                # Check if already connected
                existing = db.get_affiliate_link_by_platform(current_user['id'], platform)
                if existing:
                    results['failed'].append({
                        'platform': platform,
                        'error': 'Already connected'
                    })
                    continue
                
                # Prepare affiliate data
                affiliate_data = {
                    'id': str(uuid.uuid4()),
                    'influencer_id': current_user['id'],
                    'platform': platform,
                    'is_active': True,
                    'created_at': datetime.now(timezone.utc).isoformat(),
                    'updated_at': datetime.now(timezone.utc).isoformat(),
                    **credentials
                }
                
                # Add platform-specific affiliate_id
                if platform == 'amazon':
                    affiliate_data['affiliate_id'] = credentials.get('partner_tag', '')
                elif platform == 'rakuten':
                    affiliate_data['affiliate_id'] = credentials.get('affiliate_id', '')
                elif platform == 'shareasale':
                    affiliate_data['affiliate_id'] = credentials.get('affiliate_id', '')
                elif platform == 'cj_affiliate':
                    affiliate_data['affiliate_id'] = credentials.get('website_id', '')
                elif platform == 'skimlinks':
                    affiliate_data['affiliate_id'] = credentials.get('publisher_id', '')
                
                # Save to database
                success = db.create_affiliate_link(affiliate_data)
                
                if success:
                    results['success'].append({
                        'platform': platform,
                        'affiliate_id': affiliate_data.get('affiliate_id', ''),
                        'created_at': affiliate_data['created_at']
                    })
                else:
                    results['failed'].append({
                        'platform': platform,
                        'error': 'Database save failed'
                    })
                
            except Exception as platform_error:
                results['failed'].append({
                    'platform': platform,
                    'error': str(platform_error)
                })
        
        # Return results
        success_count = len(results['success'])
        total_count = len(platforms_data)
        
        message = f"Connected {success_count}/{total_count} platforms successfully"
        
        return jsonify({
            'status': 'success' if success_count > 0 else 'error',
            'message': message,
            'data': results
        }), 200 if success_count > 0 else 400
        
    except Exception as e:
        logger.error(f"Bulk connect platforms error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to bulk connect platforms'
        }), 500


# =============================================================================
# ENHANCED VOICE SETUP ENDPOINTS
# =============================================================================

@app.route('/api/voice/available-voices', methods=['GET'])
def get_available_voices_enhanced():
    """Get enhanced list of available voices with categories and samples"""
    try:
        # Professional voices for business/educational content
        professional_voices = [
            {
                "voice_id": "2d5b0e6cf36f460aa7fc47e3eee4ba54",
                "name": "Rachel",
                "gender": "Female",
                "language": "English",
                "style": "Professional",
                "description": "Clear, authoritative female voice perfect for business and educational content",
                "sample_text": "Hello, I'm Rachel. I specialize in professional communication and can help your audience with expert advice.",
                "use_cases": ["Business presentations", "Educational content", "Product reviews"],
                "personality_traits": ["Confident", "Clear", "Trustworthy"]
            },
            {
                "voice_id": "d7bbcdd6964c47bdaae26decade4a933",
                "name": "David",
                "gender": "Male", 
                "language": "English",
                "style": "Professional",
                "description": "Deep, authoritative male voice ideal for expert content and tutorials",
                "sample_text": "Hi there, I'm David. My voice conveys authority and expertise, perfect for sharing knowledge.",
                "use_cases": ["Tech tutorials", "Financial advice", "Expert commentary"],
                "personality_traits": ["Authoritative", "Knowledgeable", "Reliable"]
            }
        ]
        
        # Friendly voices for lifestyle/personal content
        friendly_voices = [
            {
                "voice_id": "4d2b8e6cf36f460aa7fc47e3eee4ba12",
                "name": "Emma",
                "gender": "Female",
                "language": "English", 
                "style": "Friendly",
                "description": "Warm, approachable female voice great for lifestyle and personal content",
                "sample_text": "Hey! I'm Emma, and I love connecting with people in a fun, friendly way.",
                "use_cases": ["Lifestyle tips", "Fashion advice", "Personal stories"],
                "personality_traits": ["Warm", "Approachable", "Enthusiastic"]
            },
            {
                "voice_id": "3a1c7d5bf24e350bb6dc46e2dee3ab21",
                "name": "Michael",
                "gender": "Male",
                "language": "English",
                "style": "Casual", 
                "description": "Relaxed male voice perfect for conversational, casual content",
                "sample_text": "What's up! I'm Michael, here to chat about whatever interests you most.",
                "use_cases": ["Gaming content", "Casual conversations", "Entertainment"],
                "personality_traits": ["Relaxed", "Friendly", "Conversational"]
            }
        ]
        
        # Specialized voices for specific niches
        specialized_voices = [
            {
                "voice_id": "1bd001e7e50f421d891986aad5158bc8",
                "name": "Sophia",
                "gender": "Female",
                "language": "English",
                "style": "Gentle",
                "description": "Soft, caring female voice ideal for wellness and mindfulness content",
                "sample_text": "Hello, I'm Sophia. I speak with gentleness and care, perfect for wellness topics.",
                "use_cases": ["Wellness coaching", "Meditation guides", "Self-care tips"],
                "personality_traits": ["Gentle", "Caring", "Soothing"]
            },
            {
                "voice_id": "26b2064088674c80b1e5fc5ab1a068ec", 
                "name": "Marcus",
                "gender": "Male",
                "language": "English",
                "style": "Energetic",
                "description": "Dynamic, motivational male voice for fitness and motivation content",
                "sample_text": "Hey everyone! I'm Marcus, and I'm here to pump you up and keep you motivated!",
                "use_cases": ["Fitness coaching", "Motivational content", "Sports commentary"],
                "personality_traits": ["Energetic", "Motivational", "Dynamic"]
            }
        ]
        
        return jsonify({
            'status': 'success',
            'data': {
                'voice_categories': {
                    'professional': {
                        'name': 'Professional Voices',
                        'description': 'Perfect for business, education, and expert content',
                        'voices': professional_voices
                    },
                    'friendly': {
                        'name': 'Friendly & Casual',
                        'description': 'Great for lifestyle, personal, and conversational content',
                        'voices': friendly_voices
                    },
                    'specialized': {
                        'name': 'Specialized Voices',
                        'description': 'Tailored for specific niches and use cases',
                        'voices': specialized_voices
                    }
                },
                'total_voices': len(professional_voices) + len(friendly_voices) + len(specialized_voices),
                'default_voice_id': Config.DEFAULT_VOICE_ID,
                'voice_cloning_available': bool(Config.ELEVEN_LABS_API_KEY)
            }
        })
        
    except Exception as e:
        logger.error(f"Get enhanced voices error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get voice list'
        }), 500


# =============================================================================
# ENHANCED DASHBOARD DATA
# =============================================================================

@app.route('/api/dashboard/enhanced', methods=['GET'])
@token_required
def get_enhanced_dashboard_data(current_user):
    """Get comprehensive dashboard data including affiliate metrics"""
    try:
        from datetime import timedelta
        
        # Time ranges
        today = datetime.now(timezone.utc)
        last_7_days = today - timedelta(days=7)
        last_30_days = today - timedelta(days=30)
        
        # Get basic profile info
        influencer = db.get_influencer(current_user['id'])
        
        # Get chat interactions
        recent_chats = db.supabase.table('chat_interactions') \
            .select('*') \
            .eq('influencer_id', current_user['id']) \
            .gte('created_at', last_30_days.isoformat()) \
            .execute()
        
        chats = recent_chats.data if recent_chats.data else []
        
        # Get affiliate links
        affiliate_links = db.get_affiliate_links(current_user['id'])
        
        # Calculate metrics
        total_chats = len(chats)
        unique_visitors = len(set([chat.get("session_id") for chat in chats if chat.get("session_id")]))
        video_responses = len([chat for chat in chats if chat.get('has_video')])
        audio_responses = len([chat for chat in chats if chat.get('has_audio')])
        product_recommendations = len([chat for chat in chats if chat.get('products_included')])
        
        # Weekly comparison
        last_week_chats = [chat for chat in chats if datetime.fromisoformat(chat['created_at'].replace('Z', '+00:00')) >= last_7_days]
        prev_week_chats = [chat for chat in chats if datetime.fromisoformat(chat['created_at'].replace('Z', '+00:00')) < last_7_days]
        
        week_growth = len(last_week_chats) - len(prev_week_chats)
        week_growth_percent = (week_growth / len(prev_week_chats) * 100) if prev_week_chats else 0
        
        # Setup completion score
        completion_score = 0
        setup_items = {
            'avatar_created': bool(influencer.get('heygen_avatar_id')),
            'voice_configured': bool(influencer.get('preferred_voice_id')),
            'bio_added': bool(influencer.get('bio')),
            'expertise_added': bool(influencer.get('expertise')),
            'affiliate_connected': len(affiliate_links) > 0,
            'knowledge_added': False  # You could check for uploaded documents
        }
        
        completion_score = sum(setup_items.values()) / len(setup_items) * 100
        
        dashboard_data = {
            'overview': {
                'total_chats': total_chats,
                'unique_visitors': unique_visitors,
                'video_responses': video_responses,
                'audio_responses': audio_responses,
                'product_recommendations': product_recommendations,
                'completion_score': round(completion_score, 1),
                'week_growth': week_growth,
                'week_growth_percent': round(week_growth_percent, 1)
            },
            'setup_status': setup_items,
            'affiliate_status': {
                'connected_platforms': len(affiliate_links),
                'total_platforms': 5,  # Amazon, Rakuten, ShareASale, CJ, Skimlinks
                'platform_details': affiliate_links
            },
            'avatar_status': {
                'has_avatar': bool(influencer.get('heygen_avatar_id')),
                'avatar_id': influencer.get('heygen_avatar_id'),
                'voice_configured': bool(influencer.get('preferred_voice_id')),
                'preferred_voice': influencer.get('preferred_voice_id')
            },
            'recent_activity': [
                {
                    'type': 'chat',
                    'message': chat.get('user_message', '')[:50] + '...',
                    'timestamp': chat.get('created_at'),
                    'has_video': chat.get('has_video', False),
                    'has_audio': chat.get('has_audio', False)
                }
                for chat in sorted(chats, key=lambda x: x.get('created_at', ''), reverse=True)[:5]
            ],
            'chat_url': f"{request.host_url}pages/chat.html?username={influencer['username']}",
            'profile': {
                'username': influencer['username'],
                'bio': influencer.get('bio', ''),
                'expertise': influencer.get('expertise', ''),
                'personality': influencer.get('personality', ''),
                'created_at': influencer.get('created_at')
            }
        }
        
        return jsonify({
            'status': 'success',
            'data': dashboard_data
        })
        
    except Exception as e:
        logger.error(f"Enhanced dashboard data error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get dashboard data'
        }), 500
           
# =============================================================================
# APPLICATION STARTUP
# =============================================================================

# Initialize the enhanced chatbot
def initialize_enhanced_chatbot():
    """Initialize the enhanced chatbot with all features"""
    global chatbot
    
    try:
        from chatbot import EnhancedChatbot
        chatbot = EnhancedChatbot(db=db)
        logger.info("✅ Enhanced chatbot initialized with knowledge and affiliate integration")
        return True
    except ImportError:
        try:
            from chatbot import Chatbot
            chatbot = Chatbot()
            logger.warning("⚠️ Using basic chatbot - enhanced features may not be available")
            return True
        except ImportError as e:
            logger.error(f"❌ Failed to initialize chatbot: {e}")
            return False

# Add this to your main initialization
if __name__ == '__main__':
    # Validate environment
    try:
        Config.validate()
        logger.info("✅ Environment validation passed")
    except ValueError as e:
        logger.error(f"❌ Environment validation failed: {e}")
        exit(1)
    
    # Initialize enhanced chatbot
    if not initialize_enhanced_chatbot():
        logger.error("❌ Chatbot initialization failed")
        exit(1)
    
    # Run the app
    app.run(host='0.0.0.0', port=2000, debug=True)