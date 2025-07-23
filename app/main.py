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
    from config import Config  # Import Config from config.py
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("Please ensure all required modules are in the app directory")
    sys.exit(1)

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
    chatbot = Chatbot(db)  # Pass database instance to chatbot
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
    """Register new influencer account with improved error handling"""
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
        
        # Create user with minimal required fields
        user_data = {
            'id': str(uuid.uuid4()),
            'username': username,
            'email': email,
            'password_hash': hash_password(password),
            'bio': data.get('bio', ''),
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Try to create the user
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
        
        return jsonify({
            'status': 'success',
            'message': 'Account created successfully',
            'data': {
                'user': {
                    'id': created_user['id'],
                    'username': created_user['username'],
                    'email': created_user['email'],
                    'bio': created_user.get('bio', '')
                },
                'token': token
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

# Influencer Profile Routes

@app.route('/api/influencer/profile', methods=['GET'])
@token_required
def get_influencer_profile(current_user):
    """Get influencer profile with avatar and voice info"""
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
            'preferred_voice_id': influencer.get('preferred_voice_id', '2d5b0e6cf36f460aa7fc47e3eee4ba54'),
            'avatar_training_status': influencer.get('avatar_training_status', 'none'),
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

# Chat Routes
@app.route('/api/chat', methods=['POST'])
def chat():
    """Enhanced chat endpoint with knowledge base integration"""
    try:
        data = request.get_json()
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
            influencer = db.get_influencer_by_username(username)
        
        if not influencer:
            return jsonify({
                'status': 'error',
                'message': 'Influencer not found'
            }), 404
        
        influencer_id = influencer['id']
        influencer_name = influencer.get('username', 'the influencer')
        
        logger.info(f"💬 Chat request - User: {influencer_name}, Message: {user_message[:50]}...")
        
        # Generate response using enhanced method with knowledge base
        try:
            # Use the new knowledge-enhanced response method
            ai_response = chatbot.get_chat_response_with_knowledge(
                message=user_message,
                influencer_id=influencer_id,
                session_id=session_id,
                influencer_name=influencer_name,
                db=db  # Pass database instance for knowledge retrieval
            )
            
            logger.info(f"🤖 Generated AI response: {ai_response[:100]}...")
            
        except Exception as ai_error:
            logger.error(f"AI response generation failed: {ai_error}")
            # Fallback to basic response
            ai_response = chatbot.get_fallback_response(user_message, influencer_name)
        
        # Generate video response if avatar is available
        video_url = ""
        if influencer.get('heygen_avatar_id') and not voice_mode:
            try:
                logger.info("🎬 Generating video response...")
                
                video_url = chatbot.generate_video_response(
                    text_response=ai_response,
                    avatar_id=influencer['heygen_avatar_id'],
                    voice_id=influencer.get('preferred_voice_id')
                )
                
                if video_url:
                    logger.info(f"✅ Video generated successfully: {video_url}")
                else:
                    logger.warning("⚠️ Video generation failed, proceeding with text only")
                    
            except Exception as video_error:
                logger.error(f"Video generation error: {video_error}")
                # Continue without video
        
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
                'knowledge_used': True,  # Since we're using the enhanced method
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            
            if hasattr(db, 'store_chat_interaction'):
                db.store_chat_interaction(interaction_data)
                logger.info("📊 Chat interaction stored successfully")
            
        except Exception as storage_error:
            logger.error(f"Failed to store chat interaction: {storage_error}")
            # Continue without storing
        
        # Prepare response
        response_data = {
            'text': ai_response,
            'session_id': session_id,
            'video_url': video_url,
            'has_avatar': bool(influencer.get('heygen_avatar_id')),
            'knowledge_enhanced': True
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
    """Get public chat page information"""
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
        
        return jsonify({
            'status': 'success',
            'data': {
                'username': influencer['username'],
                'bio': influencer.get('bio', ''),
                'avatar_ready': bool(influencer.get('heygen_avatar_id')),
                'has_avatar': bool(influencer.get('heygen_avatar_id')),
                'chat_enabled': True,
                'voice_id': preferred_voice_id,
                'avatar_id': influencer.get('heygen_avatar_id')
            }
        })
        
    except Exception as e:
        logger.error(f"Get chat info error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get chat information'
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
        
        # Extract talking_photo_id correctly
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

# Voice Management Routes
@app.route('/api/avatar/list-voices', methods=['GET'])
def list_available_voices():
    """Get list of available voices for avatar creation"""
    try:
        # Extended voice list with more options
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
                'total_count': len(voices)
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
    """Save user's preferred voice"""
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
                'message': 'Voice preference saved successfully'
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
        preferred_voice_id = influencer.get('preferred_voice_id', '2d5b0e6cf36f460aa7fc47e3eee4ba54')
        
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

@app.route('/api/avatar/test-video', methods=['POST'])
@token_required
def generate_test_video(current_user):
    """Generate test video with avatar and voice"""
    try:
        data = request.get_json()
        
        avatar_id = data.get('avatar_id')
        text = data.get('text', 'Hello! This is a test of my AI avatar.')
        voice_id = data.get('voice_id')
        
        if not avatar_id:
            return jsonify({
                'status': 'error',
                'message': 'Avatar ID is required'
            }), 400
        
        # Generate video using chatbot
        try:
            video_url = chatbot.generate_video_response(
                text_response=text,
                avatar_id=avatar_id,
                voice_id=voice_id
            )
            
            if video_url:
                return jsonify({
                    'status': 'success',
                    'data': {
                        'video_url': video_url,
                        'text': text,
                        'voice_id': voice_id
                    }
                })
            else:
                return jsonify({
                    'status': 'processing',
                    'message': 'Video generation started',
                    'data': {
                        'video_id': f"test_{current_user['id']}_{int(datetime.now().timestamp())}",
                        'status': 'processing'
                    }
                })
                
        except Exception as video_error:
            logger.error(f"Video generation error: {video_error}")
            return jsonify({
                'status': 'error',
                'message': 'Video generation failed'
            }), 500
            
    except Exception as e:
        logger.error(f"Test video error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to generate test video'
        }), 500

@app.route('/api/avatar/video-status/<video_id>', methods=['GET'])
@token_required
def get_video_status(current_user, video_id):
    """Get status of video generation"""
    try:
        # For test videos, simulate processing
        if video_id.startswith('test_'):
            return jsonify({
                'status': 'success',
                'data': {
                    'status': 'completed',
                    'video_url': 'https://example.com/test-video.mp4',  # Mock URL
                    'progress': 100
                }
            })
        
        # For real videos, you would check HeyGen API status
        return jsonify({
            'status': 'success',
            'data': {
                'status': 'processing',
                'progress': 75
            }
        })
        
    except Exception as e:
        logger.error(f"Get video status error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get video status'
        }), 500

# Voice Cloning Routes
@app.route('/api/voice/clone', methods=['POST'])
@token_required
def create_voice_clone(current_user):
    """Create voice clone from uploaded audio samples"""
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
            if not file.filename.lower().endswith(('.mp3', '.wav', '.webm')):
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid file type: {file.filename}. Only MP3, WAV, and WebM are supported.'
                }), 400
            
            file.seek(0, 2)  # Seek to end
            size = file.tell()
            file.seek(0)  # Reset
            total_size += size
            
            if size > 10 * 1024 * 1024:  # 10MB per file
                return jsonify({
                    'status': 'error', 
                    'message': f'File {file.filename} is too large. Maximum 10MB per file.'
                }), 400
        
        if total_size > 50 * 1024 * 1024:  # 50MB total
            return jsonify({
                'status': 'error',
                'message': 'Total file size too large. Maximum 50MB total.'
            }), 400
        
        # For now, simulate voice cloning process
        # In production, you would integrate with ElevenLabs or similar service
        import uuid
        voice_id = str(uuid.uuid4())
        
        # Update user's voice ID in database
        success = db.update_influencer(current_user['id'], {
            'voice_id': voice_id,
            'preferred_voice_id': voice_id
        })
        
        if success:
            logger.info(f"✅ Voice clone created for {current_user['username']}: {voice_id}")
            return jsonify({
                'status': 'success',
                'message': 'Voice clone created successfully',
                'data': {
                    'voice_id': voice_id,
                    'voice_name': voice_name,
                    'status': 'ready'
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to save voice clone'
            }), 500
            
    except Exception as e:
        logger.error(f"Voice clone error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to create voice clone'
        }), 500

@app.route('/api/voice/text-to-speech', methods=['POST'])
@token_required
def text_to_speech(current_user):
    """Convert text to speech using user's voice"""
    try:
        data = request.get_json()
        
        text = data.get('text')
        voice_id = data.get('voice_id')
        
        if not text:
            return jsonify({
                'status': 'error',
                'message': 'Text is required'
            }), 400
        
        if not voice_id:
            # Use user's preferred voice
            influencer = db.get_influencer(current_user['id'])
            voice_id = influencer.get('preferred_voice_id', '2d5b0e6cf36f460aa7fc47e3eee4ba54')
        
        # Generate audio using chatbot's TTS functionality
        try:
            audio_url = chatbot.generate_voice_audio(text, voice_id)
            
            if audio_url:
                return jsonify({
                    'status': 'success',
                    'data': {
                        'audio_url': audio_url,
                        'text': text,
                        'voice_id': voice_id
                    }
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to generate audio'
                }), 500
                
        except Exception as tts_error:
            logger.error(f"TTS error: {tts_error}")
            return jsonify({
                'status': 'error',
                'message': 'Text-to-speech generation failed'
            }), 500
            
    except Exception as e:
        logger.error(f"Text to speech error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to convert text to speech'
        }), 500

# Analytics Routes
@app.route('/api/analytics/dashboard', methods=['GET'])
@token_required
def get_dashboard_analytics(current_user):
    """Get dashboard analytics data"""
    try:
        # Mock analytics data - in production this would come from your analytics system
        analytics_data = {
            'total_interactions': 1543,
            'chat_sessions': 342,
            'unique_visitors': 289,
            'affiliate_earnings': 456.78,
            'recent_interactions': [
                {
                    'id': '1',
                    'created_at': (datetime.now() - timedelta(minutes=5)).isoformat(),
                    'user_message': 'What products do you recommend for skincare?',
                    'bot_response': 'I recommend these amazing skincare products...',
                    'fan_id': None,
                    'product_recommendations': True
                },
                {
                    'id': '2', 
                    'created_at': (datetime.now() - timedelta(minutes=15)).isoformat(),
                    'user_message': 'Hello! How are you today?',
                    'bot_response': 'Hi there! I\'m doing great, thanks for asking!',
                    'fan_id': None,
                    'product_recommendations': False
                },
                {
                    'id': '3',
                    'created_at': (datetime.now() - timedelta(hours=1)).isoformat(), 
                    'user_message': 'Can you help me find workout equipment?',
                    'bot_response': 'Absolutely! Here are some great workout equipment options...',
                    'fan_id': None,
                    'product_recommendations': True
                }
            ]
        }
        
        return jsonify({
            'status': 'success',
            'data': analytics_data
        })
        
    except Exception as e:
        logger.error(f"Get dashboard analytics error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get analytics data'
        }), 500

@app.route('/api/analytics/promotion', methods=['GET'])
@token_required
def get_promotion_analytics(current_user):
    """Get promotion-specific analytics"""
    try:
        # Mock promotion analytics
        promotion_data = {
            'total_interactions': 1543,
            'product_interactions': 234,
            'promotion_rate': 15.2,
            'active_conversations': 89,
            'top_products': [
                {'name': 'Skincare Set', 'recommendations': 45},
                {'name': 'Workout Equipment', 'recommendations': 38}, 
                {'name': 'Fashion Accessories', 'recommendations': 29}
            ]
        }
        
        return jsonify({
            'status': 'success',
            'data': promotion_data
        })
        
    except Exception as e:
        logger.error(f"Get promotion analytics error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get promotion analytics'
        }), 500

# Settings Routes
@app.route('/api/settings', methods=['GET'])
@token_required
def get_user_settings(current_user):
    """Get user settings"""
    try:
        influencer = db.get_influencer(current_user['id'])
        
        settings = {
            'profile': {
                'username': influencer['username'],
                'email': influencer['email'],
                'bio': influencer.get('bio', ''),
                'avatar_id': influencer.get('heygen_avatar_id'),
                'voice_id': influencer.get('preferred_voice_id')
            },
            'affiliate': {
                'connected_platforms': len(db.get_affiliate_links(current_user['id'])),
                'primary_platform': None  # Would get from affiliate links
            },
            'notifications': {
                'email_notifications': True,  # Would store in database
                'chat_notifications': True
            }
        }
        
        return jsonify({
            'status': 'success',
            'data': settings
        })
        
    except Exception as e:
        logger.error(f"Get user settings error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get settings'
        }), 500
           
# Knowledge Management Routes
@app.route('/api/knowledge/personal-info', methods=['POST'])
@token_required
def save_personal_info(current_user):
    """Save influencer's personal information for knowledge base"""
    try:
        data = request.get_json()
        
        # Validate input
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        # Prepare update data
        update_data = {}
        
        # Save bio, expertise, and personality info
        if 'bio' in data:
            update_data['bio'] = data['bio'][:1000]  # Limit to 1000 chars
        if 'expertise' in data:
            update_data['expertise'] = data['expertise'][:500]  # Limit to 500 chars
        if 'personality' in data:
            update_data['personality'] = data['personality'][:500]  # Limit to 500 chars
        
        # Update influencer profile
        success = db.update_influencer(current_user['id'], update_data)
        
        if success:
            logger.info(f"✅ Personal info updated for influencer {current_user['username']}")
            return jsonify({
                'status': 'success',
                'message': 'Personal information saved successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to save personal information'
            }), 500
            
    except Exception as e:
        logger.error(f"Save personal info error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to save personal information'
        }), 500

# Affiliate Management Routes
@app.route('/api/affiliate', methods=['GET'])
@token_required
def get_affiliate_links(current_user):
    """Get all affiliate links for current user"""
    try:
        affiliate_links = db.get_affiliate_links(current_user['id'])
        
        return jsonify({
            'status': 'success',
            'data': {
                'affiliate_links': affiliate_links,
                'available_platforms': list(Config.ALL_AFFILIATE_PLATFORMS.keys()) if hasattr(Config, 'ALL_AFFILIATE_PLATFORMS') else []
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
    """Add or update affiliate link for a platform"""
    try:
        data = request.get_json()
        
        platform = data.get('platform')
        if not platform:
            return jsonify({
                'status': 'error',
                'message': 'Platform is required'
            }), 400
        
        # Determine affiliate ID based on platform
        affiliate_id = None
        if platform == 'amazon':
            affiliate_id = data.get('partner_tag')
        elif platform == 'rakuten':
            affiliate_id = data.get('merchant_id')
        elif platform == 'shareasale':
            affiliate_id = data.get('affiliate_id')
        elif platform == 'cj_affiliate':
            affiliate_id = data.get('website_id')
        elif platform == 'skimlinks':
            affiliate_id = data.get('publisher_id')
        
        if not affiliate_id:
            return jsonify({
                'status': 'error',
                'message': 'Affiliate ID is required for this platform'
            }), 400
        
        # Add the affiliate link
        result = db.add_affiliate_link(
            influencer_id=current_user['id'],
            platform=platform,
            affiliate_id=affiliate_id,
            is_primary=data.get('is_primary', False)
        )
        
        if result:
            return jsonify({
                'status': 'success',
                'message': f'{platform.title()} connected successfully',
                'data': result
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to connect platform'
            }), 500
            
    except Exception as e:
        logger.error(f"Add affiliate link error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to connect platform'
        }), 500

@app.route('/api/affiliate/<platform>', methods=['DELETE'])
@token_required
def remove_affiliate_link(current_user, platform):
    """Remove affiliate link for a platform"""
    try:
        success = db.delete_affiliate_link(current_user['id'], platform)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f'{platform.title()} disconnected successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to disconnect platform'
            }), 500
            
    except Exception as e:
        logger.error(f"Remove affiliate link error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to disconnect platform'
        }), 500

@app.route('/api/affiliate/analytics', methods=['GET'])
@token_required
def get_affiliate_analytics(current_user):
    """Get affiliate performance analytics"""
    try:
        timeframe = request.args.get('timeframe', '7d')
        
        # Mock data for now - in production this would come from your analytics system
        analytics_data = {
            'total_clicks': 1247,
            'conversions': 89,
            'commission': 456.78,
            'conversion_rate': 7.1,
            'platforms': [
                {
                    'platform': 'amazon',
                    'name': 'Amazon Associates',
                    'clicks': 856,
                    'conversions': 67,
                    'commission': 324.50,
                    'conversion_rate': 7.8
                },
                {
                    'platform': 'rakuten',
                    'name': 'Rakuten Advertising',
                    'clicks': 243,
                    'conversions': 15,
                    'commission': 87.25,
                    'conversion_rate': 6.2
                }
            ]
        }
        
        return jsonify({
            'status': 'success',
            'data': analytics_data
        })
        
    except Exception as e:
        logger.error(f"Get affiliate analytics error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get affiliate analytics'
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