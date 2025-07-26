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

# Enhanced Chat Routes
@app.route('/api/chat', methods=['POST'])
def chat():
    """FIXED: Enhanced chat endpoint with better error handling"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        user_message = data.get('message', '').strip()
        influencer_id = data.get('influencer_id')
        username = data.get('username')
        session_id = data.get('session_id')
        voice_mode = data.get('voice_mode', False)
        
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
        
        logger.info(f"💬 Chat request - User: {influencer_name}, Message: {user_message[:50]}...")
        
        # Generate response using chatbot
        try:
            if hasattr(chatbot, 'get_chat_response_with_knowledge'):
                ai_response = chatbot.get_chat_response_with_knowledge(
                    message=user_message,
                    influencer_id=influencer_id,
                    session_id=session_id,
                    influencer_name=influencer_name,
                    db=db
                )
            else:
                # Fallback to basic response
                ai_response = chatbot.get_chat_response(
                    message=user_message,
                    influencer_id=influencer_id
                )
            
            logger.info(f"🤖 Generated AI response: {ai_response[:100]}...")
            
        except Exception as ai_error:
            logger.error(f"AI response generation failed: {ai_error}")
            ai_response = f"Hi! I'm {influencer_name}'s AI assistant. I'm having some technical difficulties right now, but I'm here to help! Could you try rephrasing your question?"
        
        # Generate video response if avatar is available
        video_url = ""
        if influencer.get('heygen_avatar_id') and not voice_mode:
            try:
                logger.info("🎬 Attempting to generate video response...")
                
                # Use user's preferred voice
                preferred_voice_id = influencer.get('preferred_voice_id', Config.DEFAULT_VOICE_ID)
                
                if hasattr(chatbot, 'generate_video_response'):
                    video_url = chatbot.generate_video_response(
                        text_response=ai_response,
                        avatar_id=influencer['heygen_avatar_id'],
                        voice_id=preferred_voice_id
                    )
                
                if video_url:
                    logger.info(f"✅ Video generated successfully: {video_url}")
                else:
                    logger.warning("⚠️ Video generation failed, proceeding with text only")
                    
            except Exception as video_error:
                logger.error(f"Video generation error: {video_error}")
        
        # Generate new session ID if not provided
        if not session_id:
            session_id = str(uuid.uuid4())
        
        # Store interaction in database for analytics
        try:
            interaction_data = {
                'influencer_id': influencer_id,
                'session_id': session_id,
                'user_message': user_message,
                'bot_response': ai_response,
                'video_url': video_url,
                'has_video': bool(video_url),
                'voice_id_used': influencer.get('preferred_voice_id', Config.DEFAULT_VOICE_ID),
                'knowledge_used': True,
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            
            if hasattr(db, 'store_chat_interaction'):
                db.store_chat_interaction(interaction_data)
                logger.info("📊 Chat interaction stored successfully")
            
        except Exception as storage_error:
            logger.error(f"Failed to store chat interaction: {storage_error}")
        
        # Prepare response
        response_data = {
            'text': ai_response,
            'session_id': session_id,
            'video_url': video_url,
            'has_avatar': bool(influencer.get('heygen_avatar_id')),
            'voice_id': influencer.get('preferred_voice_id', Config.DEFAULT_VOICE_ID),
            'knowledge_enhanced': True,
            'influencer': {
                'username': influencer['username'],
                'bio': influencer.get('bio', '')
            }
        }
        
        logger.info(f"✅ Chat response completed for {influencer_name}")
        
        return jsonify({
            'status': 'success',
            'data': response_data
        })
        
    except Exception as e:
        logger.error(f"Chat endpoint error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to process chat request'
        }), 500

@app.route('/api/chat/<username>', methods=['GET'])
def get_chat_info(username):
    """FIXED: Get enhanced public chat page information"""
    try:
        logger.info(f"Getting chat info for username: {username}")
        
        # Clean username
        clean_username = username.strip().lower()
        
        influencer = db.get_influencer_by_username(clean_username)
        
        if not influencer:
            logger.warning(f"Influencer '{username}' not found")
            return jsonify({
                'status': 'error',
                'message': 'Influencer not found'
            }), 404
        
        # Get voice information with fallback
        preferred_voice_id = influencer.get('preferred_voice_id', Config.DEFAULT_VOICE_ID)
        
        # FIXED: More comprehensive response
        response_data = {
            'username': influencer['username'],
            'bio': influencer.get('bio', ''),
            'avatar_ready': bool(influencer.get('heygen_avatar_id')),
            'has_avatar': bool(influencer.get('heygen_avatar_id')),
            'chat_enabled': True,
            'voice_id': preferred_voice_id,
            'avatar_id': influencer.get('heygen_avatar_id'),
            'avatar_type': influencer.get('avatar_type', 'none'),
            'expertise': influencer.get('expertise', ''),
            'personality': influencer.get('personality', ''),
            'created_at': influencer.get('created_at'),
            'chat_url': f"{request.host_url}pages/chat.html?username={clean_username}"
        }
        
        logger.info(f"✅ Chat info retrieved for {username}")
        
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

@app.route('/api/affiliate', methods=['GET'])
@token_required
def get_affiliate_links(current_user):
    """Get all affiliate links for the current user"""
    try:
        # Get affiliate links from database
        affiliate_links = db.get_affiliate_links(current_user['id'])
        
        # Calculate stats
        stats = {
            'connected_platforms': len(affiliate_links),
            'total_products': sum(link.get('product_count', 0) for link in affiliate_links),
            'recommendations_made': sum(link.get('recommendations', 0) for link in affiliate_links),
            'earnings_potential': sum(link.get('potential_earnings', 0) for link in affiliate_links)
        }
        
        return jsonify({
            'status': 'success',
            'data': {
                'affiliate_links': affiliate_links,
                'stats': stats
            }
        })
        
    except Exception as e:
        logger.error(f"Get affiliate links error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get affiliate links'
        }), 500

@app.route('/api/affiliate', methods=['POST'])
@token_required
def add_affiliate_link(current_user):
    """Add or update an affiliate link - UPDATED for fixed column names"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        platform = data.get('platform')
        if not platform:
            return jsonify({
                'status': 'error',
                'message': 'Platform is required'
            }), 400
        
        # Validate platform
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
        
        # Add platform-specific fields (UPDATED column names)
        if platform == 'amazon':
            affiliate_data.update({
                'amazon_access_key': data.get('access_key', ''),
                'amazon_secret_key': data.get('secret_key', ''),
                'affiliate_id': data.get('partner_tag', ''),
                'partner_tag': data.get('partner_tag', '')
            })
        elif platform == 'rakuten':
            affiliate_data.update({
                'merchant_id': data.get('merchant_id', ''),
                'api_token': data.get('token', ''),
                'affiliate_id': data.get('merchant_id', '')
            })
        elif platform == 'shareasale':
            affiliate_data.update({
                'shareasale_api_token': data.get('api_token', ''),
                'shareasale_secret_key': data.get('secret_key', ''),
                'affiliate_id': data.get('affiliate_id', '')
            })
        elif platform == 'cj_affiliate':
            affiliate_data.update({
                'cj_api_key': data.get('api_key', ''),
                'website_id': data.get('website_id', ''),
                'affiliate_id': data.get('website_id', '')
            })
        elif platform == 'skimlinks':
            affiliate_data.update({
                'skimlinks_api_key': data.get('api_key', ''),
                'publisher_id': data.get('publisher_id', ''),
                'affiliate_id': data.get('publisher_id', '')
            })
        
        # Save to database
        success = db.create_affiliate_link(affiliate_data)
        
        if success:
            logger.info(f"✅ Affiliate link created for {current_user['username']}: {platform}")
            return jsonify({
                'status': 'success',
                'message': f'{platform} connected successfully',
                'data': {
                    'platform': platform,
                    'affiliate_id': affiliate_data.get('affiliate_id', ''),
                    'created_at': affiliate_data['created_at']
                }
            }), 201
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to save affiliate link'
            }), 500
            
    except Exception as e:
        logger.error(f"Add affiliate link error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to add affiliate link'
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

# =============================================================================
# APPLICATION STARTUP
# =============================================================================

def main():
    """Main application entry point"""
    logger.info("🚀 Starting Enhanced AvatarCommerce API")
    
    # Create upload directory if it doesn't exist
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    
    # Get port from environment or use default
    port = int(os.getenv('PORT', 2000))
    
    # Run application
    logger.info(f"🌐 Enhanced server starting on port {port}")
    app.run(
        host='0.0.0.0',
        port=port,
        debug=os.getenv('FLASK_ENV') == 'development'
    )

if __name__ == '__main__':
    main()