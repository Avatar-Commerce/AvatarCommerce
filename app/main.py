from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS, cross_origin
import os
import uuid
import jwt
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import logging.handlers
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import requests
import tempfile
import base64
import sys
from config import (SUPABASE_URL, SUPABASE_KEY, HEYGEN_API_KEY, 
                   SUPABASE_SERVICE_ROLE_KEY, JWT_SECRET_KEY)
from config import ALL_AFFILIATE_PLATFORMS, get_enabled_platforms
from database import Database
from chatbot import Chatbot
from supabase import create_client, Client
from flask import make_response
import time
from functools import wraps
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create logs directory if it doesn't exist
logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(logs_dir, exist_ok=True)

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

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.FileHandler('/tmp/flask_debug.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Configure logging with better Windows compatibility
def setup_logging():
    """Set up logging with Windows-compatible file handling"""
    
    # Create logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Console handler for immediate feedback
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler with Windows-safe rotation
    log_file = os.path.join(logs_dir, 'avatar_commerce.log')
    
    try:
        # Use TimedRotatingFileHandler instead of RotatingFileHandler for better Windows compatibility
        file_handler = logging.handlers.TimedRotatingFileHandler(
            log_file,
            when='midnight',  # Rotate at midnight
            interval=1,       # Every 1 day
            backupCount=7,    # Keep 7 days of logs
            encoding='utf-8'
        )
        
        # Alternative: Use a simple FileHandler if rotation causes issues
        # file_handler = logging.FileHandler(log_file, encoding='utf-8')
        
        file_handler.setLevel(logging.INFO)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s [in %(pathname)s:%(lineno)d]'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
    except Exception as e:
        # If file logging fails, continue with console logging only
        print(f"Warning: Could not set up file logging: {e}")
        print("Continuing with console logging only...")
    
    return logger

# Set up logging
logger = setup_logging()

# Alternative simple logging setup if the above still causes issues
def setup_simple_logging():
    """Fallback simple logging setup"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),  # Console output
            logging.FileHandler(
                os.path.join(logs_dir, f'avatar_commerce_{datetime.now().strftime("%Y%m%d")}.log'),
                encoding='utf-8'
            )
        ]
    )
    return logging.getLogger(__name__)

# If you continue to have issues, uncomment this line and comment out the setup_logging() call above:
# logger = setup_simple_logging()

app = Flask(__name__)
app.config['SECRET_KEY'] = JWT_SECRET_KEY
app.config["DEBUG"] = True

CORS(app, 
     resources={
         r"/api/*": {
             "origins": [
                 "http://localhost:3000",    # React dev server
                 "http://localhost:5000",    # Alternative local port
                 "http://localhost:5500",    # Live Server (VS Code)
                 "http://localhost:8080",    # Alternative local port
                 "http://127.0.0.1:3000",   # Alternative localhost
                 "http://127.0.0.1:5000",   # Alternative localhost  
                 "http://127.0.0.1:5500",   # Alternative localhost
                 "http://127.0.0.1:8080",   # Alternative localhost
                 "http://44.202.144.180",   # Your production IP
                 "http://avatarcommerce.s3-website-us-east-1.amazonaws.com"  # Your S3 bucket
             ],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization", "Accept", "X-Requested-With", "Origin"],
             "supports_credentials": False,
             "max_age": 3600
         }
     }
)

# Initialize Supabase clients
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
admin_supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# Initialize database and chatbot
db = Database()
chatbot = Chatbot(db)  # Pass the db instance to chatbot

# Enhanced preflight handling
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        origin = request.headers.get('Origin')
        
        print(f"🔄 OPTIONS preflight from: {origin}")
        print(f"🔄 Request path: {request.path}")
        print(f"🔄 Request headers: {dict(request.headers)}")
        
        # Create a proper empty response for OPTIONS
        response = make_response('', 200)  # Empty body with 200 status
        
        # Set CORS headers
        response.headers['Access-Control-Allow-Origin'] = origin if origin else '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,Accept,X-Requested-With,Origin'
        response.headers['Access-Control-Max-Age'] = '3600'
        response.headers['Content-Length'] = '0'
        
        print(f"🔄 OPTIONS response status: 200")
        print(f"🔄 OPTIONS response headers: {dict(response.headers)}")
        
        return response

# Ensure all actual requests have CORS headers
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    
    # Only log non-OPTIONS requests to reduce noise
    if request.method != 'OPTIONS':
        print(f"📝 {request.method} {request.path} from: {origin}")
        print(f"📝 Response status: {response.status}")
    
    # Add CORS headers to all responses
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = '*'
        
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,Accept,X-Requested-With,Origin'
    
    return response
    
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
@app.route('/api/register', methods=['POST'])
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

@app.route('/api/login', methods=['POST'])
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
def upload_to_storage_admin(file_content, file_path, mimetype, bucket_name="influencer-assets"):
    """Upload file using admin client to bypass RLS issues"""
    try:
        # Ensure bucket exists
        try:
            buckets = admin_supabase.storage.list_buckets()
            bucket_exists = any(b.get('name') == bucket_name for b in buckets)
            
            if not bucket_exists:
                # Create bucket
                admin_supabase.storage.create_bucket(bucket_name, {
                    "public": True,
                    "fileSizeLimit": 10485760,  # 10MB
                    "allowedMimeTypes": ["image/jpeg", "image/png", "image/webp", "image/jpg"]
                })
                logger.info(f"Created bucket: {bucket_name}")
        except Exception as bucket_error:
            logger.warning(f"Bucket creation/check failed: {bucket_error}")
        
        # Upload file using admin client
        upload_response = admin_supabase.storage.from_(bucket_name).upload(
            path=file_path,
            file=file_content,
            file_options={
                "content-type": mimetype,
                "upsert": True  # Allow overwrite
            }
        )
        
        # Generate public URL
        public_url = f"{SUPABASE_URL}/storage/v1/object/public/{bucket_name}/{file_path}"
        
        return {
            "success": True,
            "public_url": public_url,
            "file_path": file_path
        }
        
    except Exception as e:
        logger.error(f"Admin storage upload failed: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

# Replace the file validation section in your create_avatar function with this:

@app.route('/api/avatar/create', methods=['POST'])
@influencer_token_required
def create_avatar(current_user):
    try:
        # Debug logging
        logger.info(f"Avatar creation request from user: {current_user.get('username', 'unknown')}")
        logger.info(f"Request method: {request.method}")
        logger.info(f"Request content type: {request.content_type}")
        logger.info(f"Request files: {list(request.files.keys())}")
        
        # 1. Validate request - Check for file
        file = None
        file_field_name = None
        
        # Check common field names
        possible_field_names = ['file', 'avatar_image', 'image', 'upload', 'photo']
        
        for field_name in possible_field_names:
            if field_name in request.files:
                file = request.files[field_name]
                file_field_name = field_name
                logger.info(f"Found file in field: {field_name}")
                break
        
        if not file:
            error_msg = f"No file uploaded. Expected fields: {possible_field_names}. Found: {list(request.files.keys())}"
            logger.error(error_msg)
            return jsonify({
                "message": error_msg,
                "status": "error",
                "debug": {
                    "files_received": list(request.files.keys()),
                    "form_data": list(request.form.keys()),
                    "content_type": request.content_type
                }
            }), 400
        
        if file.filename == '':
            return jsonify({
                "message": "Empty filename",
                "status": "error"
            }), 400
        
        # 2. Improved file validation using extension (more reliable than MIME type)
        logger.info(f"Validating file: {file.filename}, MIME type: {file.mimetype}")
        
        # Get file extension
        file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        allowed_extensions = {'png', 'jpg', 'jpeg', 'webp'}
        
        if file_extension not in allowed_extensions:
            return jsonify({
                "message": f"Invalid file extension '.{file_extension}'. Allowed: {', '.join(['.' + ext for ext in allowed_extensions])}",
                "status": "error",
                "debug": {
                    "filename": file.filename,
                    "detected_extension": file_extension,
                    "allowed_extensions": list(allowed_extensions),
                    "mime_type": file.mimetype
                }
            }), 400
        
        # 3. Check file size
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)     # Reset to beginning
        
        MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
        MIN_FILE_SIZE = 1024  # 1KB
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({
                "message": f"File too large: {file_size/1024/1024:.2f}MB. Maximum allowed: {MAX_FILE_SIZE/1024/1024}MB",
                "status": "error",
                "debug": {
                    "file_size_bytes": file_size,
                    "file_size_mb": round(file_size/1024/1024, 2),
                    "max_size_mb": MAX_FILE_SIZE/1024/1024
                }
            }), 413
        
        if file_size < MIN_FILE_SIZE:
            return jsonify({
                "message": f"File too small: {file_size} bytes. Minimum: {MIN_FILE_SIZE} bytes",
                "status": "error"
            }), 400
        
        logger.info(f"File validation passed: {file.filename}, {file_size} bytes, extension: .{file_extension}")
        
        # 4. Read file content
        try:
            file_content = file.read()
            file.seek(0)  # Reset for potential reuse
            
            if not file_content:
                return jsonify({
                    "message": "Empty file content",
                    "status": "error"
                }), 400
                
        except Exception as read_error:
            logger.error(f"File read error: {str(read_error)}")
            return jsonify({
                "message": f"Failed to read uploaded file: {str(read_error)}",
                "status": "error"
            }), 400
        
        # 5. Generate clean filename with proper extension mapping
        username = current_user['username']
        timestamp = int(datetime.now().timestamp())
        
        # Map extensions to ensure consistency
        extension_mapping = {
            'jpg': 'jpg',
            'jpeg': 'jpg',
            'png': 'png',
            'webp': 'webp'
        }
        
        clean_extension = extension_mapping.get(file_extension, 'jpg')
        clean_filename = f"{username}_avatar_{timestamp}.{clean_extension}"
        
        # Determine MIME type based on extension (more reliable than file.mimetype)
        mime_type_mapping = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'webp': 'image/webp'
        }
        
        mimetype = mime_type_mapping.get(file_extension, 'image/jpeg')
        
        logger.info(f"Processing file: {clean_filename}, size: {len(file_content)} bytes, type: {mimetype}")
        
        # 6. Upload to Supabase storage
        bucket_name = "influencer-assets"
        file_path = f"avatars/{username}/{clean_filename}"
        
        try:
            # Ensure bucket exists
            try:
                buckets = admin_supabase.storage.list_buckets()
                bucket_exists = any(b.get('name') == bucket_name for b in buckets)
                
                if not bucket_exists:
                    admin_supabase.storage.create_bucket(bucket_name, {
                        "public": True,
                        "allowed_mime_types": ["image/jpeg", "image/png", "image/webp"]
                    })
                    logger.info(f"Created bucket: {bucket_name}")
            except Exception as bucket_error:
                logger.warning(f"Bucket creation/check failed: {bucket_error}")
            
            # Upload file using admin client
            upload_response = admin_supabase.storage.from_(bucket_name).upload(
                path=file_path,
                file=file_content,
                file_options={
                    "content-type": mimetype,
                    "upsert": True  # Allow overwrite
                }
            )
            
            # Generate public URL
            public_url = f"{SUPABASE_URL}/storage/v1/object/public/{bucket_name}/{file_path}"
            logger.info(f"File uploaded to: {public_url}")
            
        except Exception as storage_error:
            logger.error(f"Storage upload failed: {str(storage_error)}")
            return jsonify({
                "message": f"Failed to store file: {str(storage_error)}",
                "status": "error",
                "debug": {
                    "storage_error": str(storage_error),
                    "file_path": file_path,
                    "bucket_name": bucket_name
                }
            }), 500
        
        # 7. Create HeyGen avatar using the improved function
        if not HEYGEN_API_KEY:
            return jsonify({
                "message": "HeyGen API key not configured",
                "status": "error",
                "data": {"public_url": public_url}
            }), 500

        try:
            logger.info("Starting HeyGen avatar creation...")
            
            # Use the improved HeyGen creation function
            heygen_result = create_heygen_custom_avatar(file_content, clean_filename, username)
            
            if heygen_result.get("success"):
                avatar_id = heygen_result.get("avatar_id")
                
                # Update influencer record with avatar information
                update_data = {
                    "heygen_avatar_id": avatar_id,
                    "original_asset_path": file_path,
                    "avatar_creation_method": heygen_result.get("method", "unknown"),
                    "avatar_created_at": datetime.now().isoformat()
                }
                
                update_response = admin_supabase.table("influencers").update(update_data).eq("id", current_user["id"]).execute()
                
                if update_response.data:
                    logger.info(f"✅ Avatar created successfully: {avatar_id}")
                    return jsonify({
                        "message": "Avatar created successfully!",
                        "status": "success",
                        "data": {
                            "avatar_id": avatar_id,
                            "public_url": public_url,
                            "method": heygen_result.get("method"),
                            "filename": clean_filename,
                            "file_extension": clean_extension,
                            "mime_type": mimetype
                        }
                    }), 200
                else:
                    logger.error("Failed to update influencer record")
                    return jsonify({
                        "message": "Avatar created but failed to update profile",
                        "status": "partial_success",
                        "data": {"avatar_id": avatar_id, "public_url": public_url}
                    }), 200
                    
            else:
                error_msg = heygen_result.get("error", "Unknown HeyGen error")
                logger.error(f"HeyGen avatar creation failed: {error_msg}")
                return jsonify({
                    "message": f"Avatar creation failed: {error_msg}",
                    "status": "error",
                    "data": {
                        "public_url": public_url,
                        "heygen_response": heygen_result.get("heygen_response")
                    }
                }), 500
                
        except Exception as heygen_error:
            logger.error(f"HeyGen API error: {str(heygen_error)}")
            return jsonify({
                "message": f"HeyGen API error: {str(heygen_error)}",
                "status": "error",
                "data": {"public_url": public_url}
            }), 500

    except Exception as e:
        logger.error(f"Avatar creation failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "message": f"Avatar creation failed: {str(e)}",
            "status": "error"
        }), 500

def attempt_custom_avatar_creation(file_content, filename, username):
    """Attempt custom avatar creation - expect this to fail with current plan"""
    
    if not HEYGEN_API_KEY:
        return {"success": False, "error": "No API key"}
    
    import time
    avatar_name = f"{username}_custom_{int(time.time())}"
    
    # Try the most likely endpoints based on debug results
    methods = [
        {
            "name": "Direct Photo Avatar V2",
            "url": "https://api.heygen.com/v2/photo_avatar/create",
            "field": "image"
        },
        {
            "name": "Avatar Group Creation",
            "url": "https://api.heygen.com/v2/photo_avatar/avatar_group/create", 
            "field": "image"
        },
        {
            "name": "Legacy Photo Avatar",
            "url": "https://api.heygen.com/v1/photo_avatar/create",
            "field": "file"
        }
    ]
    
    for method in methods:
        try:
            logger.info(f"Trying {method['name']}...")
            
            headers = {"X-Api-Key": HEYGEN_API_KEY}
            
            files = {
                method["field"]: (filename, file_content, 'image/jpeg')
            }
            
            data = {"name": avatar_name}
            
            response = requests.post(
                method["url"],
                headers=headers,
                files=files,
                data=data,
                timeout=60
            )
            
            logger.info(f"{method['name']} response: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                if not result.get("error"):
                    avatar_id = result.get("data", {}).get("id")
                    if avatar_id:
                        logger.info(f"✅ Custom avatar created: {avatar_id}")
                        return {
                            "success": True,
                            "avatar_id": avatar_id,
                            "method": method["name"]
                        }
            
            # Log the failure but continue
            logger.info(f"{method['name']} failed: {response.text[:200]}")
            
        except Exception as e:
            logger.info(f"{method['name']} exception: {str(e)}")
            continue
    
    logger.info("All custom avatar methods failed - this is expected")
    return {"success": False, "error": "Custom avatar creation not available"}

def select_best_matching_avatar(current_user):
    """Select the best avatar from available options"""
    
    if not HEYGEN_API_KEY:
        return None
    
    try:
        headers = {
            "X-Api-Key": HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        response = requests.get(
            "https://api.heygen.com/v2/avatars",
            headers=headers,
            timeout=15
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to get avatars: {response.status_code}")
            return None
        
        avatars_data = response.json()
        avatars = avatars_data.get("data", {}).get("avatars", [])
        
        if not avatars:
            return None
        
        # Smart avatar selection based on username/preferences
        username = current_user.get("username", "").lower()
        
        # Priority 1: Professional/Business avatars
        professional_avatars = []
        for avatar in avatars:
            name = avatar.get("name", "").lower()
            if any(keyword in name for keyword in ["professional", "business", "suit", "formal", "presenter", "host"]):
                professional_avatars.append(avatar)
        
        # Priority 2: Gender-appropriate avatars (if we can infer from username)
        gender_appropriate = []
        male_indicators = ["john", "mike", "alex", "david", "robert", "james", "william", "richard", "thomas", "charles"]
        female_indicators = ["jane", "mary", "patricia", "jennifer", "linda", "elizabeth", "barbara", "susan", "jessica", "sarah"]
        
        preferred_gender = None
        if any(indicator in username for indicator in male_indicators):
            preferred_gender = "male"
        elif any(indicator in username for indicator in female_indicators):
            preferred_gender = "female"
        
        if preferred_gender:
            for avatar in (professional_avatars if professional_avatars else avatars):
                gender = avatar.get("gender", "").lower()
                if gender == preferred_gender:
                    gender_appropriate.append(avatar)
        
        # Selection priority
        candidates = gender_appropriate if gender_appropriate else professional_avatars if professional_avatars else avatars
        
        # Filter out inappropriate avatars
        filtered_candidates = []
        excluded_keywords = ["child", "kid", "baby", "cartoon", "anime", "elderly"]
        
        for avatar in candidates:
            name = avatar.get("name", "").lower()
            if not any(excluded in name for excluded in excluded_keywords):
                filtered_candidates.append(avatar)
        
        # Select the first good candidate
        selected = filtered_candidates[0] if filtered_candidates else avatars[0]
        
        logger.info(f"Selected avatar: {selected.get('name')} (ID: {selected.get('avatar_id')})")
        
        return {
            "avatar_id": selected.get("avatar_id"),
            "name": selected.get("name", "Professional Avatar"),
            "gender": selected.get("gender", "Unknown")
        }
        
    except Exception as e:
        logger.error(f"Error selecting avatar: {str(e)}")
        return None

def check_heygen_quota():
    """Check HeyGen quota before attempting avatar creation"""
    if not HEYGEN_API_KEY:
        return {
            "success": False,
            "message": "HeyGen API key not configured"
        }
    
    try:
        headers = {
            "X-Api-Key": HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        response = requests.get(
            "https://api.heygen.com/v1/user/remaining_quota",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            quota_data = response.json()
            remaining = quota_data.get("data", {}).get("remaining_quota", 0)
            
            if remaining <= 0:
                return {
                    "success": False,
                    "message": "No HeyGen credits remaining. Please check your account and renew if needed."
                }
            else:
                logger.info(f"HeyGen quota check: {remaining} credits remaining")
                return {
                    "success": True,
                    "remaining": remaining
                }
        else:
            logger.warning(f"Quota check failed: {response.status_code}")
            # Continue anyway - quota endpoint might not be available
            return {"success": True}
            
    except Exception as e:
        logger.warning(f"Quota check error: {str(e)}")
        # Continue anyway - don't block on quota check failure
        return {"success": True}


def create_heygen_custom_avatar(file_content, filename, username):
    """
    Create custom avatar using HeyGen Pro API - improved implementation
    Handles the 'asset data must be provided' error properly
    """
    
    if not HEYGEN_API_KEY:
        return {
            "success": False,
            "error": "HeyGen API key not configured"
        }
    
    import time
    avatar_name = f"{username}_avatar_{int(time.time())}"
    
    # Method 1: Direct photo avatar creation (most likely to work)
    logger.info("Attempting Method 1: Direct photo avatar creation")
    try:
        headers = {
            "X-Api-Key": HEYGEN_API_KEY
        }
        
        # CRITICAL FIX: Use the correct file field name and ensure proper multipart format
        files = {
            'image': (filename, file_content, 'image/jpeg')  # HeyGen expects 'image' field
        }
        
        data = {
            'name': avatar_name
        }
        
        logger.info(f"Creating avatar with name: {avatar_name}")
        logger.info(f"File size: {len(file_content)} bytes")
        
        response = requests.post(
            "https://api.heygen.com/v2/photo_avatar/create",
            headers=headers,
            files=files,
            data=data,
            timeout=120
        )
        
        logger.info(f"Method 1 response: {response.status_code}")
        logger.info(f"Method 1 body: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            
            # Check for success
            if not result.get("error"):
                avatar_id = result.get("data", {}).get("id")
                if avatar_id:
                    logger.info(f"✅ Direct avatar creation successful: {avatar_id}")
                    return {
                        "success": True,
                        "avatar_id": avatar_id,
                        "method": "direct_photo_avatar_creation",
                        "heygen_response": result
                    }
            else:
                error_msg = result.get("error", {}).get("message", "Unknown error")
                logger.error(f"Direct creation error: {error_msg}")
        
        elif response.status_code == 400:
            # Parse the error
            try:
                error_data = response.json()
                error_msg = error_data.get("message", "Bad request")
                logger.error(f"Direct creation 400 error: {error_msg}")
            except:
                error_msg = "Invalid request format"
        
        elif response.status_code == 401:
            return {
                "success": False,
                "error": "Invalid HeyGen API key. Please check your API configuration.",
                "heygen_response": response.text
            }
        
        elif response.status_code == 403:
            return {
                "success": False,
                "error": "HeyGen API access forbidden. Please check your account permissions and plan.",
                "heygen_response": response.text
            }
        
        else:
            logger.warning(f"Direct creation failed with status {response.status_code}")
        
    except requests.exceptions.Timeout:
        logger.error("Direct creation timeout")
    except Exception as e:
        logger.error(f"Direct creation exception: {str(e)}")
    
    # Method 2: Asset upload then avatar creation (fallback)
    logger.info("Attempting asset upload then avatar creation...")
    try:
        headers = {
            "X-Api-Key": HEYGEN_API_KEY
        }
        
        # CRITICAL FIX: Ensure proper file format for asset upload
        files = {
            'file': (filename, file_content, 'image/jpeg')  # Asset upload expects 'file' field
        }
        
        logger.info("Uploading asset to HeyGen...")
        
        asset_response = requests.post(
            "https://upload.heygen.com/v1/asset",
            headers=headers,
            files=files,
            timeout=60
        )
        
        logger.info(f"Asset upload response: {asset_response.status_code}")
        logger.info(f"Asset upload body: {asset_response.text}")
        
        if asset_response.status_code == 200:
            asset_data = asset_response.json()
            
            if asset_data.get("code") == 100:
                asset_info = asset_data.get("data", {})
                asset_id = asset_info.get("id")
                asset_url = asset_info.get("url")
                
                if asset_id and asset_url:
                    logger.info(f"Asset uploaded successfully: {asset_id}")
                    
                    # Create avatar using the asset
                    avatar_payload = {
                        "name": avatar_name,
                        "image_url": asset_url
                    }
                    
                    avatar_headers = {
                        "X-Api-Key": HEYGEN_API_KEY,
                        "Content-Type": "application/json"
                    }
                    
                    # Try different avatar creation endpoints
                    avatar_endpoints = [
                        "https://api.heygen.com/v2/photo_avatar/create",
                        "https://api.heygen.com/v1/photo_avatar/create"
                    ]
                    
                    for endpoint in avatar_endpoints:
                        try:
                            logger.info(f"Trying avatar creation at: {endpoint}")
                            
                            avatar_response = requests.post(
                                endpoint,
                                headers=avatar_headers,
                                json=avatar_payload,
                                timeout=60
                            )
                            
                            logger.info(f"Avatar creation response: {avatar_response.status_code}")
                            logger.info(f"Avatar creation body: {avatar_response.text}")
                            
                            if avatar_response.status_code == 200:
                                avatar_data = avatar_response.json()
                                
                                if not avatar_data.get("error"):
                                    avatar_id = avatar_data.get("data", {}).get("id")
                                    
                                    if avatar_id:
                                        logger.info(f"✅ Asset-based avatar creation successful: {avatar_id}")
                                        return {
                                            "success": True,
                                            "avatar_id": avatar_id,
                                            "asset_id": asset_id,
                                            "method": f"asset_then_create_{endpoint.split('/')[-1]}",
                                            "heygen_response": avatar_data
                                        }
                            
                        except Exception as endpoint_error:
                            logger.warning(f"Endpoint {endpoint} failed: {str(endpoint_error)}")
                            continue
                    
                    return {
                        "success": False,
                        "error": "Asset uploaded but avatar creation failed. Please try again with a different image.",
                        "heygen_response": asset_data
                    }
                else:
                    return {
                        "success": False,
                        "error": "Asset upload incomplete - missing asset ID or URL",
                        "heygen_response": asset_data
                    }
            else:
                error_msg = asset_data.get("message", "Asset upload failed")
                return {
                    "success": False,
                    "error": f"Asset upload failed: {error_msg}",
                    "heygen_response": asset_data
                }
        else:
            return {
                "success": False,
                "error": f"Asset upload failed with status {asset_response.status_code}",
                "heygen_response": asset_response.text
            }
        
    except Exception as e:
        logger.error(f"Asset upload method failed: {str(e)}")
    
    # If all methods failed
    return {
        "success": False,
        "error": "All avatar creation methods failed. Please ensure your image clearly shows a single face and try again. If the issue persists, contact support."
    }

def try_heygen_avatar_creation(file_content, filename, username):
    """Try multiple methods to create HeyGen avatar"""
    
    if not HEYGEN_API_KEY:
        return {
            "success": False,
            "error": "HeyGen API key not configured"
        }
    
    import time
    
    # Method 1: Direct photo avatar creation (most likely to work)
    logger.info("Attempting Method 1: Direct photo avatar creation")
    try:
        headers = {
            "X-Api-Key": HEYGEN_API_KEY
        }
        
        files = {
            'image': (filename, file_content, 'image/jpeg')
        }
        
        data = {
            'name': f'{username}_avatar_{int(time.time())}'
        }
        
        response = requests.post(
            "https://api.heygen.com/v2/photo_avatar/create",
            headers=headers,
            files=files,
            data=data,
            timeout=120
        )
        
        logger.info(f"Method 1 response: {response.status_code}")
        logger.info(f"Method 1 body: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            if not result.get("error"):
                avatar_id = result.get("data", {}).get("id")
                if avatar_id:
                    return {
                        "success": True,
                        "avatar_id": avatar_id,
                        "method": "direct_photo_avatar_creation"
                    }
        
    except Exception as e:
        logger.warning(f"Method 1 failed: {str(e)}")
    
    # Method 2: Asset upload then avatar creation
    logger.info("Attempting Method 2: Asset upload then avatar creation")
    try:
        headers = {
            "X-Api-Key": HEYGEN_API_KEY
        }
        
        # Try different file field names
        for field_name in ['file', 'image', 'asset']:
            try:
                files = {
                    field_name: (filename, file_content, 'image/jpeg')
                }
                
                response = requests.post(
                    "https://upload.heygen.com/v1/asset",
                    headers=headers,
                    files=files,
                    timeout=60
                )
                
                logger.info(f"Method 2.{field_name} response: {response.status_code}")
                logger.info(f"Method 2.{field_name} body: {response.text}")
                
                if response.status_code == 200:
                    asset_data = response.json()
                    if asset_data.get("code") == 100:
                        asset_info = asset_data.get("data", {})
                        asset_id = asset_info.get("id")
                        asset_url = asset_info.get("url")
                        
                        if asset_id and asset_url:
                            # Now create photo avatar using the asset
                            avatar_payload = {
                                "name": f"{username}_avatar_{int(time.time())}",
                                "image_url": asset_url
                            }
                            
                            avatar_headers = {
                                "X-Api-Key": HEYGEN_API_KEY,
                                "Content-Type": "application/json"
                            }
                            
                            avatar_response = requests.post(
                                "https://api.heygen.com/v2/photo_avatar/create",
                                headers=avatar_headers,
                                json=avatar_payload,
                                timeout=60
                            )
                            
                            if avatar_response.status_code == 200:
                                avatar_data = avatar_response.json()
                                if not avatar_data.get("error"):
                                    avatar_id = avatar_data.get("data", {}).get("id")
                                    if avatar_id:
                                        return {
                                            "success": True,
                                            "avatar_id": avatar_id,
                                            "asset_id": asset_id,
                                            "method": f"asset_upload_then_create_{field_name}"
                                        }
                        break  # If we got this far, the upload worked but avatar creation failed
                        
            except Exception as field_error:
                logger.warning(f"Method 2.{field_name} failed: {str(field_error)}")
                continue
        
    except Exception as e:
        logger.warning(f"Method 2 failed: {str(e)}")
    
    # Method 3: Try with explicit content type headers
    logger.info("Attempting Method 3: With explicit headers")
    try:
        headers = {
            "X-Api-Key": HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        files = {
            'file': (filename, file_content, 'image/jpeg')
        }
        
        response = requests.post(
            "https://upload.heygen.com/v1/asset",
            headers=headers,
            files=files,
            timeout=60
        )
        
        logger.info(f"Method 3 response: {response.status_code}")
        logger.info(f"Method 3 body: {response.text}")
        
        if response.status_code == 200:
            asset_data = response.json()
            if asset_data.get("code") == 100:
                # Continue with avatar creation as in Method 2
                asset_info = asset_data.get("data", {})
                asset_id = asset_info.get("id")
                asset_url = asset_info.get("url")
                
                if asset_id and asset_url:
                    avatar_payload = {
                        "name": f"{username}_avatar_{int(time.time())}",
                        "image_url": asset_url
                    }
                    
                    avatar_headers = {
                        "X-Api-Key": HEYGEN_API_KEY,
                        "Content-Type": "application/json"
                    }
                    
                    avatar_response = requests.post(
                        "https://api.heygen.com/v2/photo_avatar/create",
                        headers=avatar_headers,
                        json=avatar_payload,
                        timeout=60
                    )
                    
                    if avatar_response.status_code == 200:
                        avatar_data = avatar_response.json()
                        if not avatar_data.get("error"):
                            avatar_id = avatar_data.get("data", {}).get("id")
                            if avatar_id:
                                return {
                                    "success": True,
                                    "avatar_id": avatar_id,
                                    "asset_id": asset_id,
                                    "method": "explicit_headers"
                                }
        
    except Exception as e:
        logger.warning(f"Method 3 failed: {str(e)}")
    
    # If all methods failed, return the most common error
    return {
        "success": False,
        "error": "Failed to create avatar. Please ensure you upload a clear photo showing your face with good lighting. If the issue persists, your HeyGen account may not have avatar creation permissions."
    }

# Add endpoint to check avatar training status
@app.route('/api/avatar/status/<avatar_id>', methods=['GET'])
@influencer_token_required
def check_avatar_status(current_user, avatar_id):
    """Check avatar status - works for both custom and pre-built avatars"""
    try:
        if not HEYGEN_API_KEY:
            return jsonify({
                "message": "HeyGen API key not configured",
                "status": "error"
            }), 500
        
        headers = {
            "X-Api-Key": HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        # First, try to check if it's a custom avatar
        try:
            response = requests.get(
                f"https://api.heygen.com/v2/photo_avatar/{avatar_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                status_data = response.json()
                if not status_data.get("error"):
                    avatar_data = status_data.get("data", {})
                    status = avatar_data.get("status", "unknown")
                    
                    is_ready = status.lower() in ["completed", "ready", "success"]
                    
                    return jsonify({
                        "status": "success",
                        "data": {
                            "avatar_id": avatar_id,
                            "training_status": status,
                            "ready_for_video": is_ready,
                            "avatar_type": "custom"
                        }
                    })
        except:
            pass  # Not a custom avatar
        
        # Check if it's a pre-built avatar
        response = requests.get(
            "https://api.heygen.com/v2/avatars",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            avatars_data = response.json()
            avatars = avatars_data.get("data", {}).get("avatars", [])
            
            avatar_exists = any(avatar.get("avatar_id") == avatar_id for avatar in avatars)
            
            if avatar_exists:
                return jsonify({
                    "status": "success",
                    "data": {
                        "avatar_id": avatar_id,
                        "training_status": "completed",
                        "ready_for_video": True,
                        "avatar_type": "prebuilt"
                    }
                })
            else:
                return jsonify({
                    "message": "Avatar not found",
                    "status": "error"
                }), 404
        else:
            return jsonify({
                "message": "Failed to verify avatar",
                "status": "error"
            }), 500
            
    except Exception as e:
        logger.error(f"Avatar status check error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/avatar/account-info', methods=['GET'])
@influencer_token_required
def get_heygen_account_info(current_user):
    """Get HeyGen account information for debugging"""
    try:
        if not HEYGEN_API_KEY:
            return jsonify({
                "message": "HeyGen API key not configured",
                "status": "error"
            }), 500
        
        headers = {
            "X-Api-Key": HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        # Get account info
        response = requests.get(
            "https://api.heygen.com/v1/user/remaining_quota",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            quota_data = response.json()
            
            # Also get avatars
            avatars_response = requests.get(
                "https://api.heygen.com/v2/avatars",
                headers=headers,
                timeout=10
            )
            
            avatars_data = avatars_response.json() if avatars_response.status_code == 200 else {}
            
            return jsonify({
                "status": "success",
                "data": {
                    "quota": quota_data.get("data", {}),
                    "avatars_count": len(avatars_data.get("data", {}).get("avatars", [])),
                    "api_working": True
                }
            })
        
        else:
            return jsonify({
                "message": f"Failed to get account info: {response.status_code}",
                "status": "error"
            }), 500
            
    except Exception as e:
        logger.error(f"Account info error: {str(e)}")
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
    """Generate response using Chatbot with improved error handling"""
    try:
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

    # Extract required fields
    user_message = data.get("message", "").strip()
    influencer_id = data.get("influencer_id")
    session_id = data.get("session_id")
    voice_mode = data.get("voice_mode", False)

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
        # Get the influencer's details
        influencer = db.get_influencer(influencer_id)
        
        if not influencer:
            return jsonify({
                "status": "error",
                "message": f"Influencer not found: {influencer_id}"
            }), 404
        
        avatar_id = influencer.get("heygen_avatar_id")
        
        logger.info(f"=== CHAT REQUEST ===")
        logger.info(f"Influencer ID: {influencer_id}")
        logger.info(f"Avatar ID: {avatar_id}")
        logger.info(f"User message: {user_message}")
        logger.info(f"Voice mode: {voice_mode}")
        
        # Generate session ID if not provided
        if not session_id:
            import secrets
            session_id = secrets.token_hex(16)
        
        # Get response from Chatbot
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
        
        # Log the interaction
        try:
            db.log_chat_interaction(
                influencer_id, 
                user_message, 
                response["text"], 
                response["has_product_recommendations"],
                session_id
            )
        except Exception as log_error:
            logger.warning(f"Failed to log interaction: {str(log_error)}")
            # Don't fail the request if logging fails
        
        # Prepare response data
        response_data = {
            "text": response["text"],
            "has_product_recommendations": response["has_product_recommendations"],
            "voice_mode": voice_mode,
            "session_id": session_id,
            "video_url": response.get("video_url", ""),
            "audio_url": response.get("audio_url", ""),
            "debug_info": {
                "avatar_id": avatar_id,
                "avatar_exists": bool(avatar_id),
                "chat_response_length": len(response["chat_response"]),
                "video_generation_attempted": bool(avatar_id),
                "video_generation_success": bool(response.get("video_url"))
            }
        }
        
        return jsonify({
            "status": "success",
            "data": response_data
        })

    except Exception as e:
        logger.error(f"Chat endpoint error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Server error: {str(e)}"
        }), 500

# Public chat page info
@app.route('/api/chat/<username>', methods=['GET'])
def get_public_chat_info(username):
    """Get public chat page info for an influencer - ENHANCED VERSION"""
    try:
        logger.info(f"Getting chat info for username: {username}")
        
        # Get influencer details by username
        influencer = db.get_influencer_by_username(username)
        
        if not influencer:
            logger.warning(f"Influencer '{username}' not found")
            return jsonify({
                "message": f"Influencer '{username}' not found",
                "status": "error"
            }), 404
        
        logger.info(f"Found influencer: {influencer.get('id')} with avatar: {influencer.get('heygen_avatar_id')}")
        
        # Check if influencer has an avatar
        if not influencer.get("heygen_avatar_id"):
            logger.warning(f"Influencer {username} hasn't created their avatar yet")
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
        
        logger.info(f"Returning chat info for {username}: avatar_id={influencer.get('heygen_avatar_id')}, has_voice={has_voice}")
        
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
        logger.error(f"Get public chat info error for {username}: {str(e)}")
        return jsonify({
            "message": f"Server error: {str(e)}",
            "status": "error"
        }), 500

# Also add this OPTIONS handler to fix CORS preflight requests
@app.route('/api/chat/<username>', methods=['OPTIONS'])
def handle_chat_options(username):
    """Handle CORS preflight requests for chat endpoint"""
    response = jsonify({'status': 'ok'})
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
    return response

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

def test_heygen_account_quota(self):
    """Test HeyGen account and quota status"""
    if not self.heygen_api_key:
        print("ERROR: HeyGen API key not configured")
        return False
    
    headers = {
        "X-Api-Key": self.heygen_api_key,
        "Accept": "application/json"
    }
    
    try:
        # Check account quota
        response = requests.get(
            "https://api.heygen.com/v1/user/remaining_quota",
            headers=headers,
            timeout=10
        )
        
        print(f"Quota check response: {response.status_code}")
        
        if response.status_code == 200:
            quota_data = response.json()
            print(f"Account quota: {json.dumps(quota_data, indent=2)}")
            
            # Check if user has credits
            data = quota_data.get("data", {})
            remaining_quota = data.get("remaining_quota", 0)
            
            if remaining_quota <= 0:
                print("WARNING: No remaining quota for video generation")
                return False
            else:
                print(f"Remaining quota: {remaining_quota}")
                return True
                
        elif response.status_code == 401:
            print("ERROR: Invalid API key")
            return False
        elif response.status_code == 403:
            print("ERROR: API access forbidden")
            return False
        else:
            print(f"Quota check failed: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"Error checking quota: {str(e)}")
        return False
    
@app.route('/api/avatar/debug/<influencer_id>', methods=['GET'])
@influencer_token_required
def debug_avatar_status(current_user, influencer_id):
    """Enhanced debug endpoint to check avatar status with better type detection"""
    try:
        if current_user["id"] != influencer_id:
            return jsonify({
                "message": "Unauthorized",
                "status": "error"
            }), 403
        
        influencer = db.get_influencer(influencer_id)
        if not influencer:
            return jsonify({
                "message": "Influencer not found",
                "status": "error"
            }), 404
        
        avatar_id = influencer.get("heygen_avatar_id")
        
        # Enhanced avatar type detection
        def detect_avatar_type(avatar_id):
            if not avatar_id:
                return "none"
            # Photo avatar groups are typically 32-character alphanumeric strings without underscores
            if len(avatar_id) == 32 and avatar_id.replace('_', '').replace('-', '').isalnum() and '_' not in avatar_id and '-' not in avatar_id:
                return "photo_avatar"
            # Regular avatars often contain underscores, descriptive names, or dates
            else:
                return "regular_avatar"
        
        avatar_type = detect_avatar_type(avatar_id)
        
        debug_info = {
            "influencer_id": influencer_id,
            "username": influencer.get("username"),
            "avatar_id": avatar_id,
            "has_avatar_id": bool(avatar_id),
            "avatar_type": avatar_type,
            "avatar_ready": False,
            "avatar_details": {},
            "available_avatars_sample": []
        }
        
        if avatar_id and chatbot.heygen_api_key:
            # Check avatar readiness
            debug_info["avatar_ready"] = chatbot.check_avatar_ready_for_video(avatar_id)
            
            # Get additional avatar information from HeyGen
            headers = {
                "X-Api-Key": chatbot.heygen_api_key,
                "Accept": "application/json"
            }
            
            try:
                if avatar_type == "photo_avatar":
                    # Get photo avatar details
                    response = requests.get(
                        f"https://api.heygen.com/v2/photo_avatar/{avatar_id}",
                        headers=headers,
                        timeout=10
                    )
                    if response.status_code == 200:
                        debug_info["avatar_details"] = response.json().get("data", {})
                
                else:
                    # Get regular avatars list and find this one
                    response = requests.get(
                        "https://api.heygen.com/v2/avatars",
                        headers=headers,
                        timeout=10
                    )
                    if response.status_code == 200:
                        avatars_data = response.json()
                        avatars = avatars_data.get("data", {}).get("avatars", [])
                        
                        # Find the specific avatar
                        matching_avatar = next((avatar for avatar in avatars if avatar.get("avatar_id") == avatar_id), None)
                        if matching_avatar:
                            debug_info["avatar_details"] = matching_avatar
                        
                        # Provide sample of available avatars for debugging
                        debug_info["available_avatars_sample"] = [
                            {
                                "avatar_id": avatar.get("avatar_id"),
                                "name": avatar.get("name", "Unknown"),
                                "gender": avatar.get("gender", "Unknown")
                            }
                            for avatar in avatars[:20]  # First 20 avatars
                        ]
                        
                        # Check for similar avatar IDs
                        similar_avatars = [
                            avatar for avatar in avatars 
                            if avatar_id.lower() in avatar.get("avatar_id", "").lower() or 
                               avatar.get("avatar_id", "").lower() in avatar_id.lower()
                        ]
                        if similar_avatars:
                            debug_info["similar_avatars"] = [
                                {
                                    "avatar_id": avatar.get("avatar_id"),
                                    "name": avatar.get("name", "Unknown")
                                }
                                for avatar in similar_avatars
                            ]
            
            except Exception as api_error:
                debug_info["api_error"] = str(api_error)
        
        # Add database information
        debug_info["database_info"] = {
            "original_asset_path": influencer.get("original_asset_path"),
            "avatar_training_status": influencer.get("avatar_training_status"),
            "avatar_created_at": influencer.get("avatar_created_at"),
            "heygen_image_key": influencer.get("heygen_image_key")
        }
        
        return jsonify({
            "status": "success",
            "data": debug_info
        })
        
    except Exception as e:
        logger.error(f"Debug avatar error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Add a new endpoint to list available avatars
@app.route('/api/avatar/available', methods=['GET'])
@influencer_token_required
def get_available_avatars(current_user):
    """Get list of available HeyGen avatars"""
    try:
        if not HEYGEN_API_KEY:
            return jsonify({
                "message": "HeyGen API key not configured",
                "status": "error"
            }), 500
        
        headers = {
            "X-Api-Key": HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        # Get avatars list
        response = requests.get(
            "https://api.heygen.com/v2/avatars",
            headers=headers,
            timeout=15
        )
        
        if response.status_code == 200:
            avatars_data = response.json()
            avatars = avatars_data.get("data", {}).get("avatars", [])
            
            # Format avatar data
            formatted_avatars = [
                {
                    "avatar_id": avatar.get("avatar_id"),
                    "name": avatar.get("name", "Unknown"),
                    "gender": avatar.get("gender", "Unknown"),
                    "preview_image": avatar.get("preview_image_url", ""),
                    "preview_video": avatar.get("preview_video_url", "")
                }
                for avatar in avatars
            ]
            
            return jsonify({
                "status": "success",
                "data": {
                    "avatars": formatted_avatars,
                    "total_count": len(formatted_avatars)
                }
            })
        
        else:
            return jsonify({
                "message": f"Failed to get avatars: {response.status_code}",
                "status": "error",
                "details": response.text
            }), 500
            
    except Exception as e:
        logger.error(f"Get available avatars error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Add this to main.py
@app.route('/api/avatar/test-video', methods=['POST'])
@influencer_token_required
def test_video_generation(current_user):
    """Test video generation with detailed debugging"""
    try:
        data = request.get_json()
        test_text = data.get('text', 'Hello! This is a test of your custom AI avatar.')
        avatar_id = data.get('avatar_id') or current_user.get("heygen_avatar_id")
        
        if not avatar_id:
            return jsonify({
                "message": "No avatar ID provided or found in profile",
                "status": "error"
            }), 400
        
        logger.info(f"Testing video generation for avatar: {avatar_id}")
        
        # Check if avatar is ready first
        avatar_ready = chatbot.check_avatar_ready_for_video(avatar_id)
        
        if not avatar_ready:
            return jsonify({
                "message": "Avatar is not ready for video generation yet. Please wait for training to complete.",
                "status": "error",
                "data": {
                    "avatar_id": avatar_id,
                    "avatar_ready": False
                }
            }), 400
        
        # Test video generation
        video_url = chatbot.generate_avatar_video(test_text, current_user["id"])
        
        return jsonify({
            "status": "success" if video_url else "failed",
            "data": {
                "video_url": video_url,
                "avatar_id": avatar_id,
                "test_text": test_text,
                "avatar_ready": avatar_ready,
                "message": "Video generated successfully" if video_url else "Video generation failed - check server logs"
            }
        })
        
    except Exception as e:
        logger.error(f"Test video generation error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/avatar/quota', methods=['GET'])
@influencer_token_required  
def check_heygen_quota(current_user):
    """Check HeyGen account quota and status"""
    try:
        if not HEYGEN_API_KEY:
            return jsonify({
                "message": "HeyGen API key not configured",
                "status": "error"
            }), 500
        
        headers = {
            "X-Api-Key": HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        # Check quota
        quota_response = requests.get(
            "https://api.heygen.com/v1/user/remaining_quota",
            headers=headers,
            timeout=10
        )
        
        quota_data = {}
        if quota_response.status_code == 200:
            quota_data = quota_response.json()
        
        # Check account info if available
        account_response = requests.get(
            "https://api.heygen.com/v1/user/remaining_quota",
            headers=headers,
            timeout=10
        )
        
        return jsonify({
            "status": "success",
            "data": {
                "quota_response_code": quota_response.status_code,
                "quota_data": quota_data,
                "api_key_valid": quota_response.status_code == 200,
                "has_remaining_quota": quota_data.get("data", {}).get("remaining_quota", 0) > 0
            }
        })
        
    except Exception as e:
        logger.error(f"Check quota error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Add avatar diagnostics endpoint
@app.route('/api/avatar/diagnose', methods=['GET'])
@influencer_token_required
def diagnose_avatar_system(current_user):
    """Comprehensive avatar system diagnostics"""
    try:
        if not HEYGEN_API_KEY:
            return jsonify({
                "message": "HeyGen API key not configured",
                "status": "error"
            }), 500
        
        diagnostics = {
            "api_key_configured": bool(HEYGEN_API_KEY),
            "api_key_length": len(HEYGEN_API_KEY) if HEYGEN_API_KEY else 0,
            "user_avatar_id": current_user.get("heygen_avatar_id"),
            "tests": {}
        }
        
        headers = {
            "X-Api-Key": HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        # Test 1: API connectivity
        try:
            response = requests.get(
                "https://api.heygen.com/v2/avatars",
                headers=headers,
                timeout=10
            )
            diagnostics["tests"]["api_connectivity"] = {
                "status_code": response.status_code,
                "success": response.status_code == 200,
                "response_size": len(response.text)
            }
            
            if response.status_code == 200:
                try:
                    avatars_data = response.json()
                    avatars_count = len(avatars_data.get("data", {}).get("avatars", []))
                    diagnostics["tests"]["api_connectivity"]["available_avatars"] = avatars_count
                except:
                    pass
                    
        except Exception as e:
            diagnostics["tests"]["api_connectivity"] = {
                "error": str(e),
                "success": False
            }
        
        # Test 2: User's avatar status (if exists)
        if current_user.get("heygen_avatar_id"):
            avatar_id = current_user["heygen_avatar_id"]
            try:
                avatar_ready = chatbot.check_avatar_ready_for_video(avatar_id)
                diagnostics["tests"]["user_avatar_status"] = {
                    "avatar_id": avatar_id,
                    "ready": avatar_ready,
                    "success": True
                }
            except Exception as e:
                diagnostics["tests"]["user_avatar_status"] = {
                    "avatar_id": avatar_id,
                    "error": str(e),
                    "success": False
                }
        
        # Test 3: Upload endpoint test
        try:
            upload_response = requests.get(
                "https://upload.heygen.com/v1/asset",
                headers={"X-Api-Key": HEYGEN_API_KEY},
                timeout=10
            )
            diagnostics["tests"]["upload_endpoint"] = {
                "status_code": upload_response.status_code,
                "accessible": upload_response.status_code != 404,
                "response_preview": upload_response.text[:200] if upload_response.text else ""
            }
        except Exception as e:
            diagnostics["tests"]["upload_endpoint"] = {
                "error": str(e),
                "accessible": False
            }
        
        # Summary
        successful_tests = sum(1 for test in diagnostics["tests"].values() if test.get("success", False))
        total_tests = len(diagnostics["tests"])
        
        diagnostics["summary"] = {
            "successful_tests": successful_tests,
            "total_tests": total_tests,
            "overall_health": "good" if successful_tests >= total_tests * 0.8 else "poor",
            "ready_for_avatar_creation": diagnostics["tests"].get("api_connectivity", {}).get("success", False)
        }
        
        return jsonify({
            "status": "success",
            "data": diagnostics
        })
        
    except Exception as e:
        logger.error(f"Avatar diagnostics error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Also add a simple API key test
@app.route('/api/avatar/test-key', methods=['GET'])
@influencer_token_required
def test_heygen_key(current_user):
    """Simple HeyGen API key test"""
    try:
        if not HEYGEN_API_KEY:
            return jsonify({
                "message": "HeyGen API key not configured",
                "status": "error",
                "data": {
                    "api_key_set": False,
                    "recommendation": "Add HEYGEN_API_KEY to your environment variables"
                }
            }), 400
        
        headers = {
            "X-Api-Key": HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        # Test with the most basic endpoint
        response = requests.get(
            "https://api.heygen.com/v2/avatars",
            headers=headers,
            timeout=15
        )
        
        result = {
            "api_key_set": True,
            "api_key_length": len(HEYGEN_API_KEY),
            "status_code": response.status_code,
            "response_size": len(response.text),
            "success": response.status_code == 200
        }
        
        if response.status_code == 200:
            result["message"] = "API key is valid and working"
            result["recommendation"] = "API access confirmed - check account plan for video generation limits"
            try:
                data = response.json()
                avatar_count = len(data.get("data", {}).get("avatars", []))
                result["available_avatars"] = avatar_count
            except:
                pass
        elif response.status_code == 401:
            result["message"] = "API key is invalid or expired"
            result["recommendation"] = "Check your HeyGen API key in the dashboard"
        elif response.status_code == 403:
            result["message"] = "API key valid but access forbidden"
            result["recommendation"] = "Your account may not have API access - upgrade to API plan"
        elif response.status_code == 404:
            result["message"] = "Endpoint not found"
            result["recommendation"] = "API might not be available for your account type"
        else:
            result["message"] = f"Unexpected response: {response.status_code}"
            result["recommendation"] = "Check HeyGen service status or contact support"
            result["response_preview"] = response.text[:500]
        
        return jsonify({
            "status": "success",
            "data": result
        })
        
    except requests.exceptions.Timeout:
        return jsonify({
            "message": "Request timed out",
            "status": "error",
            "data": {
                "recommendation": "Check your internet connection or HeyGen service status"
            }
        }), 500
        
    except Exception as e:
        logger.error(f"API key test error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/avatar/change', methods=['POST'])
@influencer_token_required
def change_avatar_selection(current_user):
    """Allow user to change their avatar selection"""
    try:
        data = request.get_json()
        new_avatar_id = data.get("avatar_id")
        
        if not new_avatar_id:
            return jsonify({
                "message": "Avatar ID is required",
                "status": "error"
            }), 400
        
        # Verify the avatar exists
        headers = {
            "X-Api-Key": HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        response = requests.get(
            "https://api.heygen.com/v2/avatars",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            avatars_data = response.json()
            avatars = avatars_data.get("data", {}).get("avatars", [])
            
            selected_avatar = next((avatar for avatar in avatars if avatar.get("avatar_id") == new_avatar_id), None)
            
            if not selected_avatar:
                return jsonify({
                    "message": "Selected avatar not found",
                    "status": "error"
                }), 404
            
            # Update user's avatar
            success = db.update_influencer(current_user["id"], {
                "heygen_avatar_id": new_avatar_id,
                "avatar_training_status": "completed",
                "avatar_ready_at": int(time.time())
            })
            
            if success:
                return jsonify({
                    "message": f"Avatar changed to {selected_avatar.get('name')}",
                    "status": "success",
                    "data": {
                        "avatar_id": new_avatar_id,
                        "avatar_name": selected_avatar.get("name"),
                        "ready_for_video": True
                    }
                })
            else:
                return jsonify({
                    "message": "Failed to update avatar",
                    "status": "error"
                }), 500
        
        return jsonify({
            "message": "Failed to verify avatar",
            "status": "error"
        }), 500
            
    except Exception as e:
        logger.error(f"Change avatar error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/avatar/check-video/<video_id>', methods=['GET'])
@influencer_token_required
def check_video_status(current_user, video_id):
    """Check the status of a specific video"""
    try:
        if not HEYGEN_API_KEY:
            return jsonify({
                "message": "HeyGen API key not configured",
                "status": "error"
            }), 500
        
        headers = {
            "X-Api-Key": HEYGEN_API_KEY,
            "Accept": "application/json"
        }
        
        # Check video status
        response = requests.get(
            f"https://api.heygen.com/v1/video_status.get?video_id={video_id}",
            headers=headers,
            timeout=15
        )
        
        result = {
            "video_id": video_id,
            "status_code": response.status_code,
            "raw_response": response.text
        }
        
        if response.status_code == 200:
            try:
                data = response.json()
                result["parsed_data"] = data
                
                if "data" in data:
                    video_data = data["data"]
                    result["video_status"] = video_data.get("status")
                    result["video_url"] = video_data.get("video_url")
                    result["error"] = video_data.get("error")
                    result["duration"] = video_data.get("duration")
                    
            except json.JSONDecodeError:
                result["json_error"] = "Failed to parse response as JSON"
        
        return jsonify({
            "status": "success",
            "data": result
        })
        
    except Exception as e:
        logger.error(f"Check video status error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

@app.route('/api/debug/user/<username>', methods=['GET'])
def debug_user_info(username):
    """Debug endpoint to check user data"""
    try:
        # Get raw influencer data
        influencer = db.get_influencer_by_username(username)
        
        debug_info = {
            "username_searched": username,
            "influencer_found": influencer is not None,
            "raw_influencer_data": influencer if influencer else None
        }
        
        if influencer:
            debug_info.update({
                "has_avatar_id": influencer.get("heygen_avatar_id") is not None,
                "avatar_id": influencer.get("heygen_avatar_id"),
                "has_voice_id": influencer.get("voice_id") is not None,
                "voice_id": influencer.get("voice_id"),
                "has_bio": influencer.get("bio") is not None,
                "bio_length": len(influencer.get("bio", "")),
                "original_asset_path": influencer.get("original_asset_path")
            })
            
            # Check if we can generate the avatar preview URL
            bucket_name = "influencer-assets"
            avatar_path = influencer.get("original_asset_path", "")
            if avatar_path:
                avatar_preview_url = f"{SUPABASE_URL}/storage/v1/object/public/{bucket_name}/{avatar_path}"
                debug_info["avatar_preview_url"] = avatar_preview_url
                debug_info["supabase_url"] = SUPABASE_URL
        
        return jsonify({
            "status": "success",
            "data": debug_info
        })
        
    except Exception as e:
        logger.error(f"Debug user error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Also add a test database connection endpoint
@app.route('/api/debug/db-test', methods=['GET'])
def test_database_connection():
    """Test database connection and table access"""
    try:
        # Test getting all influencers (limited)
        influencers = admin_supabase.table("influencers").select("username, id, heygen_avatar_id").limit(5).execute()
        
        return jsonify({
            "status": "success",
            "data": {
                "database_connected": True,
                "influencers_count": len(influencers.data),
                "sample_usernames": [inf.get("username") for inf in influencers.data]
            }
        })
        
    except Exception as e:
        logger.error(f"Database test error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Add a simple test endpoint
@app.route('/api/test-cors', methods=['GET', 'POST', 'OPTIONS'])
def test_cors():
    origin = request.headers.get('Origin', 'No Origin')
    method = request.method
    
    print(f"✅ test-cors endpoint called: {method} from {origin}")
    
    # Handle different methods
    if method == 'GET':
        return jsonify({
            "status": "success",
            "message": "GET CORS test successful",
            "method": method,
            "origin": origin,
            "timestamp": datetime.utcnow().isoformat()
        })
    elif method == 'POST':
        request_data = request.get_json() if request.is_json else {}
        return jsonify({
            "status": "success", 
            "message": "POST CORS test successful",
            "method": method,
            "origin": origin,
            "received_data": request_data,
            "timestamp": datetime.utcnow().isoformat()
        })
    else:
        return jsonify({
            "status": "success",
            "message": f"{method} CORS test successful",
            "method": method,
            "origin": origin
        })

def validate_uploaded_file(file):
    """Improved file validation using extension-based approach"""
    
    if not file or file.filename == '':
        raise ValueError("No file provided or empty filename")
    
    # Get file extension
    file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    allowed_extensions = {'png', 'jpg', 'jpeg', 'webp'}
    
    if file_extension not in allowed_extensions:
        raise ValueError(f"Invalid file extension '.{file_extension}'. Allowed: {', '.join(['.' + ext for ext in allowed_extensions])}")
    
    # Check file size
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)     # Reset to beginning
    
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    MIN_FILE_SIZE = 1024  # 1KB
    
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {file_size/1024/1024:.2f}MB. Maximum: {MAX_FILE_SIZE/1024/1024}MB")
    
    if file_size < MIN_FILE_SIZE:
        raise ValueError(f"File too small: {file_size} bytes. Minimum: {MIN_FILE_SIZE} bytes")
    
    return True

@app.route('/api/avatar/test-upload', methods=['POST'])
@influencer_token_required
def test_avatar_upload(current_user):
    """Test file upload without creating avatar - FIXED VERSION"""
    try:
        if 'file' not in request.files:
            return jsonify({
                "message": "No file uploaded",
                "status": "error"
            }), 400
            
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({
                "message": "Empty filename",
                "status": "error"
            }), 400

        # Read file content
        file_content = file.read()
        file.seek(0)
        
        # Basic file validation
        if not file.mimetype.startswith('image/'):
            return jsonify({
                "message": "File must be an image",
                "status": "error"
            }), 400
        
        # Test HeyGen asset upload only
        if HEYGEN_API_KEY:
            upload_headers = {
                "X-Api-Key": HEYGEN_API_KEY
            }
            
            # CRITICAL FIX: Use correct format for HeyGen
            files = {
                'file': (file.filename, file_content, file.mimetype or 'image/jpeg')
            }
            
            try:
                response = requests.post(
                    "https://upload.heygen.com/v1/asset",
                    headers=upload_headers,
                    files=files,
                    timeout=30
                )
                
                response_data = {}
                try:
                    response_data = response.json()
                except:
                    response_data = {"raw_response": response.text}
                
                return jsonify({
                    "status": "success",
                    "data": {
                        "file_size": len(file_content),
                        "file_type": file.mimetype,
                        "filename": file.filename,
                        "heygen_response_code": response.status_code,
                        "heygen_response": response_data,
                        "upload_test": "completed",
                        "success": response.status_code == 200 and response_data.get("code") == 100
                    }
                })
                
            except Exception as e:
                return jsonify({
                    "message": f"Upload test failed: {str(e)}",
                    "status": "error"
                }), 500
        else:
            return jsonify({
                "message": "HeyGen API key not configured",
                "status": "error"
            }), 500
            
    except Exception as e:
        logger.error(f"Test upload error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

def validate_environment():
    """Validate all required environment variables"""
    required_vars = {
        'HEYGEN_API_KEY': HEYGEN_API_KEY,
        'SUPABASE_URL': SUPABASE_URL,
        'SUPABASE_ANON_KEY': SUPABASE_ANON_KEY,
        'SUPABASE_SERVICE_ROLE_KEY': SUPABASE_SERVICE_ROLE_KEY
    }
    
    missing_vars = []
    for var_name, var_value in required_vars.items():
        if not var_value:
            missing_vars.append(var_name)
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        return False
    
    # Test HeyGen API key format
    if HEYGEN_API_KEY and not HEYGEN_API_KEY.startswith(('YTEx', 'sk-')):
        logger.warning("HeyGen API key format may be incorrect")
    
    logger.info("Environment validation passed")
    return True

# Add this diagnostic endpoint
@app.route('/api/avatar/diagnostics', methods=['GET'])
@influencer_token_required
def avatar_diagnostics(current_user):
    """Comprehensive avatar system diagnostics"""
    try:
        diagnostics = {
            "environment": {
                "heygen_api_key_set": bool(HEYGEN_API_KEY),
                "heygen_api_key_length": len(HEYGEN_API_KEY) if HEYGEN_API_KEY else 0,
                "supabase_url_set": bool(SUPABASE_URL),
                "supabase_keys_set": bool(SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY)
            },
            "tests": {}
        }
        
        # Test 1: HeyGen API connectivity
        if HEYGEN_API_KEY:
            try:
                response = requests.get(
                    "https://api.heygen.com/v2/avatars",
                    headers={"X-Api-Key": HEYGEN_API_KEY},
                    timeout=10
                )
                diagnostics["tests"]["heygen_api"] = {
                    "success": response.status_code == 200,
                    "status_code": response.status_code,
                    "response_size": len(response.text)
                }
            except Exception as e:
                diagnostics["tests"]["heygen_api"] = {
                    "success": False,
                    "error": str(e)
                }
        
        # Test 2: Supabase storage connectivity
        try:
            buckets = admin_supabase.storage.list_buckets()
            has_bucket = any(b.get('name') == 'influencer-assets' for b in buckets)
            diagnostics["tests"]["supabase_storage"] = {
                "success": True,
                "has_influencer_assets_bucket": has_bucket,
                "total_buckets": len(buckets)
            }
        except Exception as e:
            diagnostics["tests"]["supabase_storage"] = {
                "success": False,
                "error": str(e)
            }
        
        # Test 3: Database connectivity
        try:
            user_data = admin_supabase.table('influencers').select('id').eq('id', current_user['id']).execute()
            diagnostics["tests"]["database"] = {
                "success": len(user_data.data) > 0,
                "user_found": len(user_data.data) > 0
            }
        except Exception as e:
            diagnostics["tests"]["database"] = {
                "success": False,
                "error": str(e)
            }
        
        # Calculate overall health
        successful_tests = sum(1 if test.get("success") else 0 for test in diagnostics["tests"].values())
        total_tests = len(diagnostics["tests"])
        
        diagnostics["summary"] = {
            "successful_tests": successful_tests,
            "total_tests": total_tests,
            "success_rate": f"{(successful_tests/total_tests*100):.1f}%" if total_tests > 0 else "0%",
            "overall_status": "healthy" if successful_tests == total_tests else "issues_detected"
        }
        
        return jsonify({
            "status": "success",
            "data": diagnostics
        })
        
    except Exception as e:
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