from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import uuid
import jwt
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import requests
import tempfile
import base64

from config import (SUPABASE_URL, SUPABASE_KEY, HEYGEN_API_KEY, 
                   SUPABASE_SERVICE_ROLE_KEY, JWT_SECRET_KEY)
from config import ALL_AFFILIATE_PLATFORMS, get_enabled_platforms
from database import Database
from chatbot import Chatbot
from supabase import create_client, Client

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Add file handler
file_handler = RotatingFileHandler(
    'logs/avatar_commerce.log',
    maxBytes=10240,
    backupCount=10
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = JWT_SECRET_KEY
app.config["DEBUG"] = True

# Initialize Supabase clients
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
admin_supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# Initialize database and chatbot
db = Database()
chatbot = Chatbot(db)  # Pass the db instance to chatbot

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

#-----------------------
# Authentication Helpers
#-----------------------
def influencer_token_required(f):
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Invalid token format!', 'status': 'error'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing!', 'status': 'error'}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            
            # Verify it's an influencer token
            if data.get('user_type') != 'influencer':
                return jsonify({'message': 'Invalid token type!', 'status': 'error'}), 401
                
            current_user = db.get_influencer_by_username(data['username'])
            
            if not current_user:
                return jsonify({'message': 'User not found!', 'status': 'error'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!', 'status': 'error'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!', 'status': 'error'}), 401
        except Exception as e:
            return jsonify({'message': f'Token error: {str(e)}', 'status': 'error'}), 401
            
        return f(current_user, *args, **kwargs)
    
    decorated.__name__ = f.__name__
    return decorated

#-----------------------
# API Routes for Influencers
#-----------------------

# Authentication Routes for Influencers
@app.route('/api/influencer/register', methods=['POST'])
def register_influencer():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    bio = data.get("bio", "")
    affiliate_links = data.get("affiliate_links", [])

    # Validate input data
    if not username or not email or not password:
        return jsonify({
            "message": "Username, email, and password are required",
            "status": "error"
        }), 400
        
    # Username validation
    if not username.replace("_", "").isalnum():
        return jsonify({
            "message": "Username can only contain letters, numbers, and underscores",
            "status": "error"
        }), 400
        
    # Hash the password
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Check if the username or email already exists
    if db.get_influencer_by_username(username):
        return jsonify({
            "message": "Username already exists",
            "status": "error"
        }), 400
    if db.get_influencer_by_email(email):
        return jsonify({
            "message": "Email already exists",
            "status": "error"
        }), 400

    # Validate affiliate links if provided
    enabled_platforms = get_enabled_platforms()
    warnings = []
    
    for link in affiliate_links:
        platform = link.get('platform')
        affiliate_id = link.get('affiliate_id')
        
        if not platform or not affiliate_id:
            return jsonify({
                "message": "Invalid affiliate link data",
                "status": "error"
            }), 400
            
        # Check if platform exists in our system
        if platform not in ALL_AFFILIATE_PLATFORMS:
            platform_names = [info["name"] for info in ALL_AFFILIATE_PLATFORMS.values()]
            return jsonify({
                "message": f"Invalid platform '{platform}'. Available: {', '.join(platform_names)}",
                "status": "error"
            }), 400
        
        # Warn about unconfigured platforms but don't block registration
        if platform not in enabled_platforms:
            platform_name = ALL_AFFILIATE_PLATFORMS[platform]["name"]
            warnings.append(f"{platform_name} is not yet configured but your link has been saved")

    # Create user
    influencer_id = str(uuid.uuid4())
    influencer_data = {
        "id": influencer_id,
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "bio": bio if bio else None
    }

    new_influencer = db.create_influencer(influencer_data)
    if not new_influencer:
        return jsonify({
            "message": "Failed to create influencer",
            "status": "error"
        }), 500

    # Add affiliate links
    affiliate_results = []
    for i, link in enumerate(affiliate_links):
        platform = link.get('platform')
        affiliate_id = link.get('affiliate_id')
        is_primary = i == 0  # First affiliate link is primary by default
        
        result = db.add_affiliate_link(influencer_id, platform, affiliate_id, is_primary)
        if result:
            affiliate_results.append({
                "platform": platform,
                "platform_name": ALL_AFFILIATE_PLATFORMS[platform]["name"],
                "affiliate_id": affiliate_id,
                "is_primary": is_primary,
                "configured": platform in enabled_platforms
            })

    response_data = {
        "message": "Registration successful", 
        "status": "success",
        "data": {
            "id": new_influencer["id"],
            "username": new_influencer["username"],
            "email": new_influencer["email"],
            "bio": new_influencer.get("bio", ""),
            "chat_page_url": f"/chat/{username}",
            "affiliate_links": affiliate_results
        }
    }
    
    if warnings:
        response_data["warnings"] = warnings

    return jsonify(response_data), 201

@app.route('/api/influencer/login', methods=['POST'])
def login_influencer():
    try:
        # Get JSON data from request
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({
                "message": "Username and password are required",
                "status": "error"
            }), 400

        # Fetch user from database
        influencer = db.get_influencer_by_username(username)

        if not influencer:
            return jsonify({
                "message": "Invalid username or password",
                "status": "error"
            }), 401

        # Hash the input password for comparison
        hashed_input_password = hashlib.sha256(password.encode()).hexdigest()

        # Compare hashed passwords
        if influencer["password_hash"] != hashed_input_password:
            return jsonify({
                "message": "Invalid username or password",
                "status": "error"
            }), 401

        # Generate JWT token
        token_payload = {
            "username": influencer["username"],
            "id": influencer["id"],
            "user_type": "influencer",
            "exp": datetime.utcnow() + timedelta(days=30)  # Token expires in 30 days
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({
            "message": "Login successful",
            "status": "success",
            "data": {
                "id": influencer["id"],
                "username": influencer["username"],
                "email": influencer["email"],
                "bio": influencer.get("bio", ""),
                "avatar_id": influencer.get("heygen_avatar_id"),
                "voice_id": influencer.get("voice_id"),
                "chat_page_url": f"/chat/{username}",
                "has_avatar": influencer.get("heygen_avatar_id") is not None,
                "token": token
            }
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Profile Management
@app.route('/api/influencer/profile', methods=['GET'])
@influencer_token_required
def get_influencer_profile(current_user):
    try:
        bucket_name = "influencer-assets"
        avatar_path = current_user.get("original_asset_path", "")
        avatar_preview_url = f"{SUPABASE_URL}/storage/v1/object/public/{bucket_name}/{avatar_path}" if avatar_path else ""
        
        return jsonify({
            "status": "success",
            "data": {
                "id": current_user["id"],
                "username": current_user["username"],
                "email": current_user["email"],
                "bio": current_user.get("bio", ""),
                "avatar_id": current_user.get("heygen_avatar_id"),
                "voice_id": current_user.get("voice_id"),
                "profile_image_url": avatar_preview_url,
                "chat_page_url": f"/chat/{current_user['username']}",
                "has_avatar": current_user.get("heygen_avatar_id") is not None
            }
        })
    except Exception as e:
        logger.error(f"Get profile error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/influencer/profile', methods=['PUT'])
@influencer_token_required
def update_influencer_profile(current_user):
    try:
        data = request.get_json()
        
        updates = {}
        
        if "bio" in data:
            updates["bio"] = data["bio"]
            
        if "voice_id" in data:
            updates["voice_id"] = data["voice_id"]
            
        if not updates:
            return jsonify({
                "message": "No fields to update",
                "status": "error"
            }), 400
            
        success = db.update_influencer(current_user["id"], updates)
        
        if not success:
            return jsonify({
                "message": "Failed to update profile",
                "status": "error"
            }), 500
            
        # Get updated profile data
        updated_user = db.get_influencer(current_user["id"])
        
        return jsonify({
            "message": "Profile updated successfully",
            "status": "success",
            "data": {
                "bio": updated_user.get("bio", ""),
                "voice_id": updated_user.get("voice_id")
            }
        })
    except Exception as e:
        logger.error(f"Update profile error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Avatar Management
@app.route('/api/avatar/create', methods=['POST'])
@influencer_token_required
def create_avatar(current_user):
    try:
        # 1. Validate request
        if 'file' not in request.files:
            return jsonify({
                "message": "No file uploaded",
                "status": "error"
            }), 400
            
        file = request.files['file']
        influencer_id = current_user["id"]
        
        if file.filename == '':
            return jsonify({
                "message": "Empty filename",
                "status": "error"
            }), 400

        # 2. Check file size before reading
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)  # Reset file pointer
        
        # Supabase free tier has a 2MB limit per file
        MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB in bytes
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({
                "message": f"File too large. Maximum size is {MAX_FILE_SIZE/1024/1024}MB",
                "status": "error",
                "data": {
                    "file_size_mb": round(file_size/1024/1024, 2)
                }
            }), 413

        # 3. Prepare upload
        from werkzeug.utils import secure_filename
        safe_filename = secure_filename(file.filename)
        file_path = f"avatars/original_{influencer_id}_{safe_filename}"
        bucket_name = "influencer-assets"
        file_content = file.read()

        # 4. Upload file to storage
        try:
            upload_response = admin_supabase.storage.from_(bucket_name).upload(
                path=file_path,
                file=file_content,
                file_options={"content-type": file.mimetype}
            )
            
            # Get public URL for the uploaded image
            public_url = f"{SUPABASE_URL}/storage/v1/object/public/{bucket_name}/{file_path}"
            
            # 5. Connect to HeyGen API
            try:
                heygen_headers = {
                    "X-Api-Key": HEYGEN_API_KEY,
                    "Accept": "application/json"
                }
                
                logger.info("Attempting to connect to HeyGen API...")
                
                # Test the API key by listing avatars
                test_response = requests.get(
                    "https://api.heygen.com/v2/avatars",
                    headers=heygen_headers,
                    timeout=10  # Add timeout
                )
                
                # Log detailed response for debugging
                logger.info(f"HeyGen API response: {test_response.status_code}, {test_response.text}")
                
                if test_response.status_code != 200:
                    logger.error(f"HeyGen API test failed: {test_response.text}")
                    return jsonify({
                        "message": f"HeyGen API access failed: {test_response.text}",
                        "status": "error",
                        "data": {
                            "path": file_path,
                            "public_url": public_url
                        }
                    }), 500
                
                # Process the response
                response_data = test_response.json()
                avatars = response_data.get("data", {}).get("avatars", [])
                
                if not avatars:
                    logger.error("No avatars available in HeyGen account")
                    return jsonify({
                        "message": "No avatars available in HeyGen account",
                        "status": "error",
                        "data": {
                            "path": file_path,
                            "public_url": public_url
                        }
                    }), 500
                
                # Use the first avatar in the list
                avatar_id = avatars[0].get("avatar_id")
                logger.info(f"Using HeyGen avatar: {avatar_id}")
                
                # Update database with avatar information
                db.update_influencer(influencer_id, {
                    "original_asset_path": file_path,
                    "heygen_avatar_id": avatar_id
                })
                
                return jsonify({
                    "message": "Avatar assigned successfully",
                    "status": "success",
                    "data": {
                        "path": file_path,
                        "public_url": public_url,
                        "avatar_id": avatar_id,
                        "influencer_id": influencer_id
                    }
                })
                
            except requests.exceptions.RequestException as e:
                logger.error(f"HeyGen API request failed: {str(e)}")
                return jsonify({
                    "message": f"HeyGen API request failed: {str(e)}",
                    "status": "error",
                    "data": {
                        "path": file_path,
                        "public_url": public_url
                    }
                }), 500
                
        except Exception as upload_error:
            logger.error(f"Upload error: {str(upload_error)}")
            return jsonify({
                "message": f"Upload failed: {str(upload_error)}",
                "status": "error"
            }), 500

    except Exception as e:
        logger.error(f"Avatar creation failed: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Affiliate Management
@app.route('/api/affiliate', methods=['POST'])
@influencer_token_required
def add_affiliate(current_user):
    try:
        data = request.get_json()
        platform = data.get("platform")
        affiliate_id = data.get("affiliate_id")
        is_primary = data.get("is_primary", False)
        
        if not platform or not affiliate_id:
            return jsonify({
                "message": "Platform and affiliate_id are required",
                "status": "error"
            }), 400
        
        # Check if platform exists (even if not enabled yet)
        if platform not in ALL_AFFILIATE_PLATFORMS:
            platform_names = [info["name"] for info in ALL_AFFILIATE_PLATFORMS.values()]
            return jsonify({
                "message": f"Invalid platform. Available platforms: {', '.join(platform_names)}",
                "status": "error"
            }), 400
        
        # Warn if platform is not yet configured but allow saving
        enabled_platforms = get_enabled_platforms()
        if platform not in enabled_platforms:
            warning_message = f"Note: {ALL_AFFILIATE_PLATFORMS[platform]['name']} is not yet configured in the system. Your affiliate link has been saved and will work once the platform is configured."
        else:
            warning_message = None
            
        # Add/update affiliate link
        result = db.add_affiliate_link(current_user["id"], platform, affiliate_id, is_primary)
        
        if not result:
            return jsonify({
                "message": "Failed to add affiliate link",
                "status": "error"
            }), 500
            
        response_data = {
            "message": "Affiliate information added successfully",
            "status": "success",
            "data": result
        }
        
        if warning_message:
            response_data["warning"] = warning_message
            
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Add affiliate error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/affiliate', methods=['GET'])
@influencer_token_required
def get_affiliates(current_user):
    try:
        platform = request.args.get('platform')  # Optional filter by platform
        affiliate_links = db.get_affiliate_links(current_user["id"], platform)
        primary_link = db.get_primary_affiliate_link(current_user["id"])
        
        return jsonify({
            "status": "success",
            "data": {
                "affiliate_links": affiliate_links,
                "primary_affiliate": primary_link
            }
        })
    except Exception as e:
        logger.error(f"Get affiliates error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/affiliate/<platform>', methods=['DELETE'])
@influencer_token_required
def delete_affiliate(current_user, platform):
    try:
        # Validate platform
        valid_platforms = ['rakuten', 'amazon', 'shareasale', 'cj_affiliate']
        if platform not in valid_platforms:
            return jsonify({
                "message": f"Invalid platform. Must be one of: {', '.join(valid_platforms)}",
                "status": "error"
            }), 400
        
        # Delete affiliate link
        success = db.delete_affiliate_link(current_user["id"], platform)
        
        if not success:
            return jsonify({
                "message": "Failed to delete affiliate link",
                "status": "error"
            }), 500
        
        return jsonify({
            "message": f"{platform} affiliate link deleted successfully",
            "status": "success"
        })
        
    except Exception as e:
        logger.error(f"Delete affiliate error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# GET available affiliate platforms
@app.route('/api/affiliate/platforms', methods=['GET'])
def get_available_platforms():
    """Get list of available affiliate platforms (both enabled and disabled)"""
    try:
        enabled_platforms = get_enabled_platforms()
        
        # Return all platforms with their status
        platforms_with_status = {}
        for platform_key, platform_info in ALL_AFFILIATE_PLATFORMS.items():
            platforms_with_status[platform_key] = {
                "name": platform_info["name"],
                "enabled": platform_key in enabled_platforms,
                "configured": platform_key in enabled_platforms
            }
        
        return jsonify({
            "status": "success",
            "data": {
                "platforms": platforms_with_status,
                "enabled_count": len(enabled_platforms),
                "total_count": len(ALL_AFFILIATE_PLATFORMS)
            }
        })
    except Exception as e:
        logger.error(f"Get platforms error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500
    
# Voice Chat Features
@app.route('/api/voice/speech-to-text', methods=['POST'])
def speech_to_text():
    """Convert speech audio to text using OpenAI Whisper API"""
    try:
        if 'audio' not in request.files:
            return jsonify({
                "message": "No audio file uploaded",
                "status": "error"
            }), 400
            
        audio_file = request.files['audio']
        
        if audio_file.filename == '':
            return jsonify({
                "message": "Empty filename",
                "status": "error"
            }), 400
            
        # Read the file content
        audio_content = audio_file.read()
        
        # Transcribe using chatbot's transcribe_audio method
        transcribed_text = chatbot.transcribe_audio(audio_content)
        
        if not transcribed_text:
            return jsonify({
                "message": "Failed to transcribe audio",
                "status": "error"
            }), 500
            
        return jsonify({
            "status": "success",
            "data": {
                "text": transcribed_text
            }
        })
    
    except Exception as e:
        logger.error(f"Speech to text error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/voice/text-to-speech', methods=['POST'])
def text_to_speech():
    """Convert text to speech audio using ElevenLabs API"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "message": "Request must be JSON",
                "status": "error"
            }), 400
            
        text = data.get("text")
        # Use voice_id instead of voice_name
        voice_id = data.get("voice_id", "21m00Tcm4TlvDq8ikWAM")  # Default ElevenLabs voice ID
        
        if not text:
            return jsonify({
                "message": "Text is required",
                "status": "error"
            }), 400
            
        # Generate audio using chatbot's generate_voice_audio method with the correct parameter
        audio_url = chatbot.generate_voice_audio(text, voice_id)
        
        if not audio_url:
            return jsonify({
                "message": "Failed to generate audio",
                "status": "error"
            }), 500
            
        return jsonify({
            "status": "success",
            "data": {
                "audio_url": audio_url
            }
        })
    
    except Exception as e:
        logger.error(f"Text to speech error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/voice/clone', methods=['POST'])
@influencer_token_required
def clone_influencer_voice(current_user):
    """Create a cloned voice using ElevenLabs Voice Clone API"""
    try:
        # Check if files are uploaded
        if 'audio_samples' not in request.files:
            return jsonify({
                "message": "No audio samples uploaded",
                "status": "error"
            }), 400
            
        # Get multiple audio files
        audio_files = request.files.getlist('audio_samples')
        
        if len(audio_files) == 0 or audio_files[0].filename == '':
            return jsonify({
                "message": "No audio samples selected",
                "status": "error"
            }), 400
            
        # Validate that we have enough audio (ElevenLabs recommends at least 1 minute)
        if len(audio_files) < 3:  # Arbitrary minimum, adjust as needed
            return jsonify({
                "message": "Please upload at least 3 audio samples for better voice cloning",
                "status": "warning"
            }), 400
            
        # Get name for the voice (use username if not provided)
        voice_name = request.form.get('voice_name', f"{current_user['username']}'s Voice")
        description = request.form.get('description', f"Cloned voice for {current_user['username']}")
        
        # Read all audio files into memory
        audio_samples = []
        for audio_file in audio_files:
            audio_samples.append(audio_file.read())
        
        # Call the chatbot to create the cloned voice
        voice_id, message = chatbot.create_cloned_voice(voice_name, audio_samples, description)
        
        if not voice_id:
            return jsonify({
                "message": message,
                "status": "error"
            }), 500
            
        # Update the influencer record with the new voice ID
        db.update_influencer(current_user["id"], {"voice_id": voice_id})
        
        return jsonify({
            "message": "Voice cloned successfully",
            "status": "success",
            "data": {
                "voice_id": voice_id,
                "voice_name": voice_name
            }
        })
        
    except Exception as e:
        logger.error(f"Voice cloning error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/voice/available-voices', methods=['GET'])
def get_available_voices():
    """Get list of available ElevenLabs voices"""
    try:
        # Call the chatbot's method to get ElevenLabs voices
        voices = chatbot.get_available_voices()
        
        if not voices:
            return jsonify({
                "message": "Failed to retrieve voices from ElevenLabs",
                "status": "error"
            }), 500
            
        return jsonify({
            "status": "success",
            "data": {
                "voices": voices
            }
        })
    
    except Exception as e:
        logger.error(f"Get voices error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500
        
# Chat Functionality
@app.route('/api/chat', methods=['POST'])
def chat_message():
    """Generate response using Chatbot with optional product recommendations and voice - No authentication required"""
    try:
        # Ensure JSON data is received
        data = request.get_json()
        if not data:
            return jsonify({
                "status": "error",
                "message": "Invalid request. No JSON data provided."
            }), 400
    except Exception as e:
        logger.error(f"JSON parsing error: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Invalid JSON data: {str(e)}"
        }), 400

    # Extract required fields with error checking
    user_message = data.get("message", "").strip()
    influencer_id = data.get("influencer_id")
    session_id = data.get("session_id")  # Optional session ID for conversation tracking
    voice_mode = data.get("voice_mode", False)  # Default to false if not provided

    # Validate required fields
    if not user_message:
        return jsonify({
            "status": "error",
            "message": "Message cannot be empty"
        }), 400

    if not influencer_id:
        return jsonify({
            "status": "error", 
            "message": "Influencer ID is required"
        }), 400

    try:
        # 1. Get the influencer's details
        influencer = db.get_influencer(influencer_id)
        
        if not influencer:
            return jsonify({
                "status": "error",
                "message": f"Influencer not found: {influencer_id}"
            }), 404
        
        avatar_id = influencer.get("heygen_avatar_id")
        
        if not avatar_id:
            return jsonify({
                "status": "error",
                "message": "Influencer has no avatar. Please upload an image first."
            }), 400
        
        # 2. Generate session ID if not provided
        if not session_id:
            import secrets
            session_id = secrets.token_hex(16)
        
        # 3. Get response from Chatbot with product recommendations
        try:
            response = chatbot.get_response(
                user_message, 
                influencer_id, 
                session_id, 
                influencer.get("username"),
                voice_mode,
                influencer.get("voice_id")
            )
        except Exception as bot_error:
            logger.error(f"Chatbot error: {str(bot_error)}")
            return jsonify({
                "status": "error",
                "message": f"Error generating response: {str(bot_error)}"
            }), 500
        
        # 4. Log the interaction
        db.log_chat_interaction(
            influencer_id, 
            user_message, 
            response["text"], 
            response["has_product_recommendations"],
            session_id
        )
        
        # 5. Prepare response data
        response_data = {
            "text": response["text"],
            "video_url": response.get("video_url", ""),
            "has_product_recommendations": response["has_product_recommendations"],
            "voice_mode": voice_mode,
            "session_id": session_id  # Return session ID for future requests
        }
        
        # Add audio URL if voice mode is enabled
        if voice_mode and "audio_url" in response:
            response_data["audio_url"] = response["audio_url"]
        
        return jsonify({
            "status": "success",
            "data": response_data
        })

    except Exception as e:
        logger.error(f"Chat endpoint unexpected error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Unexpected server error: {str(e)}"
        }), 500

# Public chat page info
@app.route('/api/chat/<username>', methods=['GET'])
def get_public_chat_info(username):
    """Get public chat page info for an influencer"""
    try:
        # Get influencer details by username
        influencer = db.get_influencer_by_username(username)
        
        if not influencer:
            return jsonify({
                "message": f"Influencer '{username}' not found",
                "status": "error"
            }), 404
        
        # Check if influencer has an avatar
        if not influencer.get("heygen_avatar_id"):
            return jsonify({
                "message": f"{username} hasn't created their avatar yet",
                "status": "error"
            }), 404
            
        # Get avatar preview URL
        bucket_name = "influencer-assets"
        avatar_path = influencer.get("original_asset_path", "")
        avatar_preview_url = f"{SUPABASE_URL}/storage/v1/object/public/{bucket_name}/{avatar_path}" if avatar_path else ""
        
        # Check if voice is configured
        has_voice = influencer.get("voice_id") is not None
        
        return jsonify({
            "status": "success",
            "data": {
                "username": influencer["username"],
                "influencer_id": influencer["id"],
                "avatar_preview_url": avatar_preview_url,
                "avatar_id": influencer["heygen_avatar_id"],
                "has_voice": has_voice,
                "voice_id": influencer.get("voice_id", ""),
                "bio_snippet": influencer.get("bio", "")[:100] + "..." if influencer.get("bio") and len(influencer.get("bio")) > 100 else influencer.get("bio", ""),
                "chat_endpoint": "/api/chat",
                "voice_enabled": True  # Google TTS is always available
            }
        })
    
    except Exception as e:
        logger.error(f"Get public chat info error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Generate embed code for influencer
@app.route('/api/embed/generate', methods=['POST'])
@influencer_token_required
def generate_embed_code(current_user):
    """Generate embed code for influencer's chatbot"""
    try:
        data = request.get_json()
        
        # Get customization options
        width = data.get('width', '400px')
        height = data.get('height', '600px')
        position = data.get('position', 'bottom-right')  # bottom-right, bottom-left, custom
        theme = data.get('theme', 'default')  # default, dark, light, custom
        trigger_text = data.get('trigger_text', 'Chat with me!')
        auto_open = data.get('auto_open', False)
        custom_css = data.get('custom_css', '')
        
        # Validate influencer has avatar
        if not current_user.get("heygen_avatar_id"):
            return jsonify({
                "message": "You must create an avatar before generating embed code",
                "status": "error"
            }), 400
        
        # Generate embed script
        base_url = request.host_url.rstrip('/')  # Get the base URL dynamically
        influencer_id = current_user["id"]
        username = current_user["username"]
        
        # Create the embed code
        embed_code = f'''<!-- AvatarCommerce Chatbot Embed -->
<div id="avatarcommerce-chatbot-{influencer_id}"></div>
<script>
(function() {{
    var config = {{
        influencerId: "{influencer_id}",
        username: "{username}",
        baseUrl: "{base_url}",
        width: "{width}",
        height: "{height}",
        position: "{position}",
        theme: "{theme}",
        triggerText: "{trigger_text}",
        autoOpen: {str(auto_open).lower()},
        customCss: `{custom_css}`
    }};
    
    var script = document.createElement('script');
    script.src = config.baseUrl + '/static/embed/chatbot-widget.js';
    script.onload = function() {{
        AvatarCommerceWidget.init(config);
    }};
    document.head.appendChild(script);
    
    var link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = config.baseUrl + '/static/embed/chatbot-widget.css';
    document.head.appendChild(link);
}})();
</script>
<!-- End AvatarCommerce Chatbot Embed -->'''

        # Store embed configuration
        embed_config = {
            "influencer_id": influencer_id,
            "width": width,
            "height": height,
            "position": position,
            "theme": theme,
            "trigger_text": trigger_text,
            "auto_open": auto_open,
            "custom_css": custom_css,
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Update influencer record with embed config
        db.update_influencer(influencer_id, {"embed_config": embed_config})
        
        return jsonify({
            "status": "success",
            "data": {
                "embed_code": embed_code,
                "preview_url": f"{base_url}/embed/preview/{username}",
                "config": embed_config
            }
        })
        
    except Exception as e:
        logger.error(f"Generate embed code error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Get current embed configuration
@app.route('/api/embed/config', methods=['GET'])
@influencer_token_required
def get_embed_config(current_user):
    """Get current embed configuration for influencer"""
    try:
        embed_config = current_user.get("embed_config", {})
        
        # Set defaults if no config exists
        if not embed_config:
            embed_config = {
                "width": "400px",
                "height": "600px",
                "position": "bottom-right",
                "theme": "default",
                "trigger_text": "Chat with me!",
                "auto_open": False,
                "custom_css": ""
            }
        
        return jsonify({
            "status": "success",
            "data": {
                "config": embed_config,
                "has_avatar": current_user.get("heygen_avatar_id") is not None,
                "preview_url": f"{request.host_url.rstrip('/')}/embed/preview/{current_user['username']}"
            }
        })
        
    except Exception as e:
        logger.error(f"Get embed config error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Serve embed preview page
@app.route('/embed/preview/<username>')
def embed_preview(username):
    """Serve a preview page showing how the embedded chatbot looks"""
    try:
        # Get influencer details
        influencer = db.get_influencer_by_username(username)
        
        if not influencer:
            return f"Influencer '{username}' not found", 404
            
        if not influencer.get("heygen_avatar_id"):
            return f"{username} hasn't created their avatar yet", 404
        
        embed_config = influencer.get("embed_config", {})
        
        # Default config if none exists
        if not embed_config:
            embed_config = {
                "width": "400px",
                "height": "600px",
                "position": "bottom-right",
                "theme": "default",
                "trigger_text": "Chat with me!",
                "auto_open": False,
                "custom_css": ""
            }
        
        # Generate preview HTML
        preview_html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chatbot Preview - {username}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .preview-container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .preview-header {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .sample-content {{
            margin: 40px 0;
            padding: 20px;
            border: 1px dashed #ccc;
            background: #fafafa;
        }}
        .config-info {{
            background: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="preview-container">
        <div class="preview-header">
            <h1>Chatbot Embed Preview</h1>
            <p>This is how your chatbot will appear on websites</p>
        </div>
        
        <div class="config-info">
            <h3>Current Configuration:</h3>
            <ul>
                <li><strong>Size:</strong> {embed_config.get('width', '400px')} × {embed_config.get('height', '600px')}</li>
                <li><strong>Position:</strong> {embed_config.get('position', 'bottom-right')}</li>
                <li><strong>Theme:</strong> {embed_config.get('theme', 'default')}</li>
                <li><strong>Trigger Text:</strong> "{embed_config.get('trigger_text', 'Chat with me!')}"</li>
                <li><strong>Auto Open:</strong> {'Yes' if embed_config.get('auto_open', False) else 'No'}</li>
            </ul>
        </div>
        
        <div class="sample-content">
            <h2>Sample Website Content</h2>
            <p>This is sample content to show how your chatbot integrates with a website. The chatbot widget should appear in the {embed_config.get('position', 'bottom-right')} corner.</p>
            <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
        </div>
    </div>
    
    <!-- Embed the actual chatbot -->
    <div id="avatarcommerce-chatbot-{influencer['id']}"></div>
    <script>
    (function() {{
        var config = {{
            influencerId: "{influencer['id']}",
            username: "{username}",
            baseUrl: "{request.host_url.rstrip('/')}",
            width: "{embed_config.get('width', '400px')}",
            height: "{embed_config.get('height', '600px')}",
            position: "{embed_config.get('position', 'bottom-right')}",
            theme: "{embed_config.get('theme', 'default')}",
            triggerText: "{embed_config.get('trigger_text', 'Chat with me!')}",
            autoOpen: {str(embed_config.get('auto_open', False)).lower()},
            customCss: `{embed_config.get('custom_css', '')}`
        }};
        
        var script = document.createElement('script');
        script.src = config.baseUrl + '/static/embed/chatbot-widget.js';
        script.onload = function() {{
            AvatarCommerceWidget.init(config);
        }};
        document.head.appendChild(script);
        
        var link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = config.baseUrl + '/static/embed/chatbot-widget.css';
        document.head.appendChild(link);
    }})();
    </script>
</body>
</html>'''
        
        return preview_html
        
    except Exception as e:
        logger.error(f"Embed preview error: {str(e)}")
        return f"Error loading preview: {str(e)}", 500

# Analytics for embedded chatbots
@app.route('/api/analytics/embed', methods=['GET'])
@influencer_token_required
def get_embed_analytics(current_user):
    """Get analytics for embedded chatbot usage"""
    try:
        # Get date range from query params
        days = request.args.get('days', 30, type=int)
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get embed-specific interactions (those with referrer data)
        embed_interactions = admin_supabase.table("chat_interactions") \
            .select("created_at, session_id") \
            .eq("influencer_id", current_user["id"]) \
            .gte("created_at", start_date.isoformat()) \
            .execute()
        
        # Calculate metrics
        total_embed_chats = len(embed_interactions.data)
        unique_sessions = len(set([chat.get("session_id") for chat in embed_interactions.data if chat.get("session_id")]))
        
        # Group by date for chart
        daily_stats = {}
        for interaction in embed_interactions.data:
            date = interaction["created_at"][:10]  # YYYY-MM-DD
            daily_stats[date] = daily_stats.get(date, 0) + 1
        
        return jsonify({
            "status": "success",
            "data": {
                "total_embed_chats": total_embed_chats,
                "unique_visitors": unique_sessions,
                "daily_stats": daily_stats,
                "avg_daily_chats": total_embed_chats / days if days > 0 else 0,
                "date_range": {
                    "start": start_date.isoformat(),
                    "end": datetime.utcnow().isoformat(),
                    "days": days
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Embed analytics error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500
    
# Analytics
@app.route('/api/analytics/dashboard', methods=['GET'])
@influencer_token_required
def get_dashboard_data(current_user):
    """Get dashboard data for the influencer"""
    try:
        # Get recent chat interactions
        interactions = admin_supabase.table("chat_interactions") \
            .select("*") \
            .eq("influencer_id", current_user["id"]) \
            .order("created_at", {"ascending": False}) \
            .limit(10) \
            .execute()
            
        # Count total interactions
        total_interactions = admin_supabase.table("chat_interactions") \
            .select("count", {"count": "exact", "head": True}) \
            .eq("influencer_id", current_user["id"]) \
            .execute()
            
        # Count product recommendations
        product_interactions = admin_supabase.table("chat_interactions") \
            .select("count", {"count": "exact", "head": True}) \
            .eq("influencer_id", current_user["id"]) \
            .eq("product_recommendations", True) \
            .execute()
            
        # Get profile info
        bucket_name = "influencer-assets"
        avatar_path = current_user.get("original_asset_path", "")
        avatar_preview_url = f"{SUPABASE_URL}/storage/v1/object/public/{bucket_name}/{avatar_path}" if avatar_path else ""
            
        return jsonify({
            "status": "success",
            "data": {
                "username": current_user["username"],
                "email": current_user["email"],
                "profile_image": avatar_preview_url,
                "recent_interactions": interactions.data,
                "total_interactions": total_interactions.count if hasattr(total_interactions, 'count') else 0,
                "product_interactions": product_interactions.count if hasattr(product_interactions, 'count') else 0,
                "avatar_status": current_user.get("heygen_avatar_id") is not None,
                "affiliate_status": current_user.get("affiliate_id") is not None,
                "chat_page_url": f"/chat/{current_user['username']}"
            }
        })
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Promotion Settings Endpoints
@app.route('/api/promotion/settings', methods=['GET'])
@influencer_token_required
def get_promotion_settings(current_user):
    """Get promotion settings for the influencer"""
    try:
        settings = db.get_promotion_settings(current_user["id"])
        
        return jsonify({
            "status": "success",
            "data": settings
        })
    except Exception as e:
        logger.error(f"Get promotion settings error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/promotion/settings', methods=['PUT'])
@influencer_token_required
def update_promotion_settings(current_user):
    """Update promotion settings for the influencer"""
    try:
        data = request.get_json()
        
        # Validate inputs
        promotion_frequency = data.get("promotion_frequency")
        if promotion_frequency is not None:
            try:
                promotion_frequency = int(promotion_frequency)
                if promotion_frequency < 1:
                    return jsonify({
                        "message": "Promotion frequency must be at least 1",
                        "status": "error"
                    }), 400
            except ValueError:
                return jsonify({
                    "message": "Promotion frequency must be a number",
                    "status": "error" 
                }), 400
        
        promote_at_end = data.get("promote_at_end")
        if promote_at_end is not None:
            if not isinstance(promote_at_end, bool):
                return jsonify({
                    "message": "Promote at end must be a boolean",
                    "status": "error"
                }), 400
        
        # Build updates object
        updates = {}
        if promotion_frequency is not None:
            updates["promotion_frequency"] = promotion_frequency
        if promote_at_end is not None:
            updates["promote_at_end"] = promote_at_end
        
        # Update settings
        success = db.update_promotion_settings(current_user["id"], updates)
        
        if not success:
            return jsonify({
                "message": "Failed to update promotion settings",
                "status": "error"
            }), 500
        
        # Return updated settings
        settings = db.get_promotion_settings(current_user["id"])
        
        return jsonify({
            "message": "Promotion settings updated successfully",
            "status": "success",
            "data": settings
        })
    except Exception as e:
        logger.error(f"Update promotion settings error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Influencer Products Endpoints
@app.route('/api/promotion/products', methods=['GET'])
@influencer_token_required
def get_influencer_products(current_user):
    """Get all products for the influencer"""
    try:
        products = db.get_influencer_products(current_user["id"])
        
        return jsonify({
            "status": "success",
            "data": {
                "products": products
            }
        })
    except Exception as e:
        logger.error(f"Get influencer products error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/promotion/products', methods=['POST'])
@influencer_token_required
def add_influencer_product(current_user):
    """Add a product for the influencer to promote"""
    try:
        data = request.get_json()
        
        # Validate inputs
        product_name = data.get("product_name")
        if not product_name:
            return jsonify({
                "message": "Product name is required",
                "status": "error"
            }), 400
        
        product_query = data.get("product_query")
        if not product_query:
            return jsonify({
                "message": "Product query is required",
                "status": "error"
            }), 400
        
        is_default = data.get("is_default", False)
        
        # Add product
        product = db.add_influencer_product(
            current_user["id"],
            product_name,
            product_query,
            is_default
        )
        
        if not product:
            return jsonify({
                "message": "Failed to add product",
                "status": "error"
            }), 500
        
        return jsonify({
            "message": "Product added successfully",
            "status": "success",
            "data": product
        })
    except Exception as e:
        logger.error(f"Add influencer product error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/promotion/products/<product_id>', methods=['DELETE'])
@influencer_token_required
def delete_influencer_product(current_user, product_id):
    """Delete a product"""
    try:
        # Check if product belongs to influencer
        products = db.get_influencer_products(current_user["id"])
        product_ids = [p.get("id") for p in products]
        
        if product_id not in product_ids:
            return jsonify({
                "message": "Product not found or does not belong to you",
                "status": "error"
            }), 404
        
        # Delete product
        success = db.delete_influencer_product(product_id)
        
        if not success:
            return jsonify({
                "message": "Failed to delete product",
                "status": "error"
            }), 500
        
        return jsonify({
            "message": "Product deleted successfully",
            "status": "success"
        })
    except Exception as e:
        logger.error(f"Delete influencer product error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/promotion/products/<product_id>/set-default', methods=['POST'])
@influencer_token_required
def set_default_product(current_user, product_id):
    """Set a product as the default"""
    try:
        # Check if product belongs to influencer
        products = db.get_influencer_products(current_user["id"])
        product_ids = [p.get("id") for p in products]
        
        if product_id not in product_ids:
            return jsonify({
                "message": "Product not found or does not belong to you",
                "status": "error"
            }), 404
        
        # Set as default
        success = db.set_default_product(product_id)
        
        if not success:
            return jsonify({
                "message": "Failed to set product as default",
                "status": "error"
            }), 500
        
        return jsonify({
            "message": "Product set as default successfully",
            "status": "success"
        })
    except Exception as e:
        logger.error(f"Set default product error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/promotion/reset-counter', methods=['POST'])
@influencer_token_required
def reset_promotion_counter(current_user):
    """Reset the promotion counter for a specific session"""
    try:
        data = request.get_json()
        
        # Validate inputs
        session_id = data.get("session_id")
        if not session_id:
            return jsonify({
                "message": "Session ID is required",
                "status": "error"
            }), 400
        
        # Reset counter
        success = db.reset_conversation_counter(current_user["id"], session_id)
        
        if not success:
            return jsonify({
                "message": "Failed to reset counter",
                "status": "error"
            }), 500
        
        return jsonify({
            "message": "Counter reset successfully",
            "status": "success"
        })
    except Exception as e:
        logger.error(f"Reset counter error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Analytics enhancement for promotion tracking
@app.route('/api/analytics/dashboard', methods=['GET'])
@influencer_token_required
def get_dashboard_data(current_user):
    """Get dashboard data for the influencer"""
    try:
        # Get recent chat interactions
        interactions = admin_supabase.table("chat_interactions") \
            .select("*") \
            .eq("influencer_id", current_user["id"]) \
            .order("created_at", {"ascending": False}) \
            .limit(10) \
            .execute()
            
        # Count total interactions
        total_interactions = admin_supabase.table("chat_interactions") \
            .select("count", {"count": "exact", "head": True}) \
            .eq("influencer_id", current_user["id"]) \
            .execute()
            
        # Count product recommendations
        product_interactions = admin_supabase.table("chat_interactions") \
            .select("count", {"count": "exact", "head": True}) \
            .eq("influencer_id", current_user["id"]) \
            .eq("product_recommendations", True) \
            .execute()
            
        # Count unique sessions (approximate unique visitors)
        unique_sessions = admin_supabase.table("chat_interactions") \
            .select("session_id") \
            .eq("influencer_id", current_user["id"]) \
            .execute()
        
        # Count unique session IDs
        unique_session_count = len(set([interaction.get("session_id") for interaction in unique_sessions.data if interaction.get("session_id")]))
        
        # Get profile info
        bucket_name = "influencer-assets"
        avatar_path = current_user.get("original_asset_path", "")
        avatar_preview_url = f"{SUPABASE_URL}/storage/v1/object/public/{bucket_name}/{avatar_path}" if avatar_path else ""
            
        return jsonify({
            "status": "success",
            "data": {
                "username": current_user["username"],
                "email": current_user["email"],
                "profile_image": avatar_preview_url,
                "recent_interactions": interactions.data,
                "total_interactions": total_interactions.count if hasattr(total_interactions, 'count') else 0,
                "product_interactions": product_interactions.count if hasattr(product_interactions, 'count') else 0,
                "unique_visitors": unique_session_count,
                "avatar_status": current_user.get("heygen_avatar_id") is not None,
                "affiliate_status": len(db.get_affiliate_links(current_user["id"])) > 0,
                "chat_page_url": f"/chat/{current_user['username']}"
            }
        })
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Main Application Entry
if __name__ == "__main__":
    # Make sure all required environment variables are set
    required_env_vars = ["SUPABASE_URL", "SUPABASE_KEY", "HEYGEN_API_KEY", "RAKUTEN_TOKEN", "JWT_SECRET_KEY"]
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        exit(1)
        
    port = int(os.getenv("PORT", 2000))
    app.run(host="0.0.0.0", port=port)