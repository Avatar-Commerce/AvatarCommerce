from flask import Flask, request, jsonify
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

def fan_token_required(f):
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
            
            # Verify it's a fan token
            if data.get('user_type') != 'fan':
                return jsonify({'message': 'Invalid token type!', 'status': 'error'}), 401
                
            current_user = db.get_fan_by_username(data['username'])
            
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
@app.route('/api/auth/influencer/register', methods=['POST'])
def register_influencer():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    affiliate_id = data.get("affiliate_id", "")
    bio = data.get("bio", "")

    # Validate input data
    if not username or not email or not password:
        return jsonify({
            "message": "Username, email, and password are required",
            "status": "error"
        }), 400
        
    # Username validation - alphanumeric and underscore only
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

    # Create user
    influencer_id = str(uuid.uuid4())
    influencer_data = {
        "id": influencer_id,
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "affiliate_id": affiliate_id if affiliate_id else None,
        "bio": bio if bio else None
    }

    new_influencer = db.create_influencer(influencer_data)
    if not new_influencer:
        return jsonify({
            "message": "Failed to create influencer",
            "status": "error"
        }), 500

    # Generate chat page URL
    chat_page_url = f"/chat/{username}"
    
    # Add affiliate information if provided
    if affiliate_id:
        db.add_affiliate_link(influencer_id, "amazon", affiliate_id)

    return jsonify({
        "message": "Registration successful", 
        "status": "success",
        "data": {
            "id": new_influencer["id"],
            "username": new_influencer["username"],
            "email": new_influencer["email"],
            "bio": new_influencer.get("bio", ""),
            "chat_page_url": chat_page_url
        }
    }), 201

@app.route('/api/auth/influencer/login', methods=['POST'])
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
        
        if not platform or not affiliate_id:
            return jsonify({
                "message": "Platform and affiliate_id are required",
                "status": "error"
            }), 400
            
        # Add/update affiliate link
        result = db.add_affiliate_link(current_user["id"], platform, affiliate_id)
        
        if not result:
            return jsonify({
                "message": "Failed to add affiliate link",
                "status": "error"
            }), 500
            
        # Also update the influencer's primary affiliate ID
        db.update_influencer(current_user["id"], {"affiliate_id": affiliate_id})
        
        return jsonify({
            "message": "Affiliate information added successfully",
            "status": "success",
            "data": result
        })
        
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
        affiliate_links = db.get_affiliate_links(current_user["id"])
        return jsonify({
            "status": "success",
            "data": {
                "affiliate_links": affiliate_links
            }
        })
    except Exception as e:
        logger.error(f"Get affiliates error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

#-----------------------
# API Routes for Fans
#-----------------------

@app.route('/api/auth/fan/register', methods=['POST'])
def register_fan():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    # Validate input data
    if not username or not email or not password:
        return jsonify({
            "message": "Username, email, and password are required",
            "status": "error"
        }), 400
        
    # Username validation - alphanumeric and underscore only
    if not username.replace("_", "").isalnum():
        return jsonify({
            "message": "Username can only contain letters, numbers, and underscores",
            "status": "error"
        }), 400
        
    # Hash the password
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Check if the username or email already exists
    if db.get_fan_by_username(username):
        return jsonify({
            "message": "Username already exists",
            "status": "error"
        }), 400
    if db.get_fan_by_email(email):
        return jsonify({
            "message": "Email already exists",
            "status": "error"
        }), 400

    # Create user
    fan_id = str(uuid.uuid4())
    fan_data = {
        "id": fan_id,
        "username": username,
        "email": email,
        "password_hash": password_hash
    }

    new_fan = db.create_fan(fan_data)
    if not new_fan:
        return jsonify({
            "message": "Failed to create fan account",
            "status": "error"
        }), 500

    return jsonify({
        "message": "Registration successful", 
        "status": "success",
        "data": {
            "id": new_fan["id"],
            "username": new_fan["username"],
            "email": new_fan["email"]
        }
    }), 201

@app.route('/api/auth/fan/login', methods=['POST'])
def login_fan():
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
        fan = db.get_fan_by_username(username)

        if not fan:
            return jsonify({
                "message": "Invalid username or password",
                "status": "error"
            }), 401

        # Hash the input password for comparison
        hashed_input_password = hashlib.sha256(password.encode()).hexdigest()

        # Compare hashed passwords
        if fan["password_hash"] != hashed_input_password:
            return jsonify({
                "message": "Invalid username or password",
                "status": "error"
            }), 401

        # Generate JWT token
        token_payload = {
            "username": fan["username"],
            "id": fan["id"],
            "user_type": "fan",
            "exp": datetime.utcnow() + timedelta(days=30)  # Token expires in 30 days
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({
            "message": "Login successful",
            "status": "success",
            "data": {
                "id": fan["id"],
                "username": fan["username"],
                "email": fan["email"],
                "token": token
            }
        }), 200

    except Exception as e:
        logger.error(f"Fan login error: {str(e)}")
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
    """Generate response using Chatbot with optional product recommendations and voice"""
    data = request.get_json()
    if not data:
        return jsonify({
            "message": "Request must be JSON",
            "status": "error"
        }), 400
    
    user_message = data.get("message", "")
    influencer_id = data.get("influencer_id")
    fan_id = data.get("fan_id")  # Optional fan ID for conversation tracking
    voice_mode = data.get("voice_mode", False)  # Default to false if not provided
    
    if not user_message or not influencer_id:
        return jsonify({
            "message": "message and influencer_id are required",
            "status": "error"
        }), 400

    try:
        # 1. Get the influencer's details
        influencer = db.get_influencer(influencer_id)
        
        if not influencer:
            return jsonify({
                "message": f"Influencer not found: {influencer_id}",
                "status": "error"
            }), 404
        
        avatar_id = influencer.get("heygen_avatar_id")
        
        if not avatar_id:
            return jsonify({
                "message": "Influencer has no avatar. Please upload an image first.",
                "status": "error"
            }), 400
        
        # 2. Verify fan ID if provided
        if fan_id:
            fan = db.get_fan(fan_id)
            if not fan:
                return jsonify({
                    "message": f"Fan not found: {fan_id}",
                    "status": "error"
                }), 404
        
        # 3. Get response from Chatbot with product recommendations
        response = chatbot.get_response(
            user_message, 
            influencer_id, 
            fan_id, 
            influencer.get("username"),
            voice_mode,
            influencer.get("voice_id")
        )
        
        # 4. Log the interaction
        db.log_chat_interaction(
            influencer_id, 
            user_message, 
            response["text"], 
            response["has_product_recommendations"],
            fan_id
        )
        
        # 5. Prepare response data
        response_data = {
            "text": response["text"],
            "video_url": response["video_url"],
            "has_product_recommendations": response["has_product_recommendations"],
            "voice_mode": voice_mode
        }
        
        # Add audio URL if voice mode is enabled
        if voice_mode and "audio_url" in response:
            response_data["audio_url"] = response["audio_url"]
        
        return jsonify({
            "status": "success",
            "data": response_data
        })

    except Exception as e:
        logger.error(f"Chat endpoint error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
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

# Fan Chat History
@app.route('/api/fan/chat-history', methods=['GET'])
@fan_token_required
def get_fan_chat_history(current_user):
    """Get chat history for a fan with an influencer"""
    try:
        influencer_id = request.args.get('influencer_id')
        limit = request.args.get('limit', 20)
        
        try:
            limit = int(limit)
            if limit < 1 or limit > 100:
                limit = 20  # Default if limit is out of range
        except ValueError:
            limit = 20  # Default if limit is not a valid integer
        
        if not influencer_id:
            return jsonify({
                "message": "influencer_id is required",
                "status": "error"
            }), 400
            
        # Check if influencer exists
        influencer = db.get_influencer(influencer_id)
        if not influencer:
            return jsonify({
                "message": f"Influencer not found: {influencer_id}",
                "status": "error"
            }), 404
            
        # Get chat history
        chat_history = db.get_chat_history(influencer_id, current_user["id"], limit)
        
        return jsonify({
            "status": "success",
            "data": {
                "chat_history": chat_history,
                "influencer": {
                    "username": influencer["username"],
                    "id": influencer["id"]
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Get fan chat history error: {str(e)}")
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

# Main Application Entry
if __name__ == "__main__":
    # Make sure all required environment variables are set
    required_env_vars = ["SUPABASE_URL", "SUPABASE_KEY", "HEYGEN_API_KEY", "APIFY_API_KEY", "JWT_SECRET_KEY"]
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        exit(1)
        
    port = int(os.getenv("PORT", 8000))
    app.run(host="0.0.0.0", port=port)