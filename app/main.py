from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import uuid
import jwt
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
import requests

from config import (SUPABASE_URL, SUPABASE_KEY, HEYGEN_API_KEY, 
                   SUPABASE_SERVICE_ROLE_KEY, JWT_SECRET_KEY)
from database import Database
from chatbot import Chatbot
from supabase import create_client, Client
from flasgger import Swagger, swag_from

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

# Configure Swagger for API documentation
app.config['SWAGGER'] = {
    'title': 'Influencer Avatar Commerce Mobile API',
    'uiversion': 3,
    'specs_route': '/api/docs/',
    'headers': [],
    'specs': [
        {
            'endpoint': 'apispec',
            'route': '/api/docs/apispec.json',
            'rule_filter': lambda rule: True,
            'model_filter': lambda tag: True,
        }
    ],
}

swagger_template = {
    "info": {
        "title": "Influencer Avatar Commerce Mobile API",
        "description": "API for mobile application to manage influencer avatars and product recommendations",
        "version": "1.0.0",
    },
    "schemes": ["http", "https"],
    "tags": [
        {
            "name": "Auth",
            "description": "Authentication operations"
        },
        {
            "name": "Avatars",
            "description": "Operations with digital avatars"
        },
        {
            "name": "Chat",
            "description": "Chat and video generation"
        },
        {
            "name": "Affiliate",
            "description": "Affiliate management operations"
        },
        {
            "name": "Analytics",
            "description": "Analytics and statistics"
        }
    ]
}

swagger = Swagger(app, template=swagger_template)

# Initialize Supabase clients
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
admin_supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# Initialize database and chatbot
db = Database()
chatbot = Chatbot()

#-----------------------
# Authentication Helper
#-----------------------
def token_required(f):
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
    
    # Preserve the function name and docstring
    decorated.__name__ = f.__name__
    decorated.__doc__ = f.__doc__
    
    return decorated

#-----------------------
# API Routes
#-----------------------

# Authentication Routes
@app.route('/api/auth/register', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'description': 'Register a new influencer',
    'consumes': ['application/json'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string', 'example': 'johndoe'},
                    'email': {'type': 'string', 'example': 'john@example.com'},
                    'password': {'type': 'string', 'example': 'securepass123'},
                    'affiliate_id': {'type': 'string', 'example': 'amzn-123456', 'required': False}
                },
                'required': ['username', 'email', 'password']
            }
        }
    ],
    'responses': {
        '201': {
            'description': 'User created successfully'
        },
        '400': {'description': 'Bad request - invalid input data'},
        '500': {'description': 'Internal server error'}
    }
})
def register():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    affiliate_id = data.get("affiliate_id", "")

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
        "affiliate_id": affiliate_id if affiliate_id else None
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
            "chat_page_url": chat_page_url
        }
    }), 201

@app.route('/api/auth/login', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'description': 'Login and get JWT token',
    'consumes': ['application/json'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string', 'example': 'johndoe'},
                    'password': {'type': 'string', 'example': 'securepass123'}
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        '200': {
            'description': 'Login successful'
        },
        '401': {'description': 'Authentication failed'},
        '500': {'description': 'Internal server error'}
    }
})
def login():
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
                "avatar_id": influencer.get("heygen_avatar_id"),
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

# Avatar Management
@app.route('/api/avatar/create', methods=['POST'])
@token_required
@swag_from({
    'tags': ['Avatars'],
    'description': 'Create HeyGen avatar from uploaded media',
    'consumes': ['multipart/form-data'],
    'parameters': [
        {
            'name': 'file',
            'in': 'formData',
            'type': 'file',
            'required': True,
            'description': 'Media file for avatar creation'
        }
    ],
    'responses': {
        '200': {
            'description': 'Avatar created successfully'
        },
        '400': {'description': 'Bad request'},
        '500': {'description': 'Internal server error'}
    }
})
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
            
            # 5. Create HeyGen avatar using the uploaded image
            try:
                # Call HeyGen API to create an avatar
                heygen_headers = {"X-Api-Key": HEYGEN_API_KEY}
                
                # Create avatar using HeyGen API
                avatar_response = requests.post(
                    f"https://api.heygen.com/v1/avatar.create",
                    json={
                        "image_url": public_url, 
                        "name": f"Influencer_{influencer_id}"
                    },
                    headers=heygen_headers
                )
                
                if avatar_response.status_code != 200:
                    logger.error(f"HeyGen avatar creation failed: {avatar_response.text}")
                    return jsonify({
                        "message": f"HeyGen avatar creation failed: {avatar_response.text}",
                        "status": "error",
                        "data": {
                            "path": file_path,
                            "public_url": public_url
                        }
                    }), 500
                
                # Extract avatar ID from HeyGen response
                avatar_data = avatar_response.json()
                avatar_id = avatar_data.get("avatar_id")
                
                if not avatar_id:
                    logger.error(f"HeyGen response missing avatar_id: {avatar_data}")
                    return jsonify({
                        "message": "HeyGen response missing avatar_id",
                        "status": "error",
                        "data": {
                            "path": file_path,
                            "public_url": public_url,
                            "heygen_response": avatar_data
                        }
                    }), 500
                
                # 6. Update database with avatar information
                db.update_influencer(influencer_id, {
                    "original_asset_path": file_path,
                    "heygen_avatar_id": avatar_id
                })
                
                return jsonify({
                    "message": "Avatar created successfully",
                    "status": "success",
                    "data": {
                        "path": file_path,
                        "public_url": public_url,
                        "avatar_id": avatar_id,
                        "influencer_id": influencer_id
                    }
                })
                
            except Exception as heygen_error:
                logger.error(f"HeyGen API error: {str(heygen_error)}")
                return jsonify({
                    "message": f"HeyGen API error: {str(heygen_error)}",
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
@token_required
@swag_from({
    'tags': ['Affiliate'],
    'description': 'Add or update affiliate information',
    'consumes': ['application/json'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'platform': {'type': 'string', 'example': 'amazon'},
                    'affiliate_id': {'type': 'string', 'example': 'amzn-123456'}
                },
                'required': ['platform', 'affiliate_id']
            }
        }
    ],
    'responses': {
        '200': {
            'description': 'Affiliate info updated successfully'
        },
        '400': {'description': 'Bad request'},
        '500': {'description': 'Internal server error'}
    }
})
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
@token_required
@swag_from({
    'tags': ['Affiliate'],
    'description': 'Get all affiliate links for the current user',
    'responses': {
        '200': {
            'description': 'List of affiliate links'
        },
        '500': {'description': 'Internal server error'}
    }
})
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

# Chat Functionality
@app.route('/api/chat', methods=['POST'])
@swag_from({
    'tags': ['Chat'],
    'description': 'Send a message to the chatbot and get a response with video',
    'consumes': ['application/json'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string', 'example': 'Can you recommend some running shoes?'},
                    'influencer_id': {'type': 'string', 'example': '123e4567-e89b-12d3-a456-426614174000'}
                },
                'required': ['message', 'influencer_id']
            }
        }
    ],
    'responses': {
        '200': {
            'description': 'Chatbot response with video'
        },
        '400': {'description': 'Bad request'},
        '404': {'description': 'Influencer not found'},
        '500': {'description': 'Internal server error'}
    }
})
def chat_message():
    """Generate response using Chatbot with optional product recommendations"""
    data = request.get_json()
    if not data:
        return jsonify({
            "message": "Request must be JSON",
            "status": "error"
        }), 400
    
    user_message = data.get("message", "")
    influencer_id = data.get("influencer_id")
    
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
        
        # 2. Get response from Chatbot with product recommendations
        response = chatbot.get_response(user_message, influencer.get("affiliate_id", ""), influencer.get("username"))
        
        # 3. Log the interaction
        db.log_chat_interaction(
            influencer_id, 
            user_message, 
            response["text"], 
            response["has_product_recommendations"]
        )
        
        return jsonify({
            "status": "success",
            "data": {
                "text": response["text"],
                "video_url": response["video_url"],
                "has_product_recommendations": response["has_product_recommendations"]
            }
        })

    except Exception as e:
        logger.error(f"Chat endpoint error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Public chat page info
@app.route('/api/chat/<username>', methods=['GET'])
@swag_from({
    'tags': ['Chat'],
    'description': 'Get public chat page info for an influencer',
    'parameters': [
        {
            'name': 'username',
            'in': 'path',
            'type': 'string',
            'required': True,
            'description': 'Influencer username'
        }
    ],
    'responses': {
        '200': {
            'description': 'Chat page info'
        },
        '404': {'description': 'Influencer not found'}
    }
})
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
        
        return jsonify({
            "status": "success",
            "data": {
                "username": influencer["username"],
                "influencer_id": influencer["id"],
                "avatar_preview_url": avatar_preview_url,
                "avatar_id": influencer["heygen_avatar_id"],
                "chat_endpoint": "/api/chat"
            }
        })
    
    except Exception as e:
        logger.error(f"Get public chat info error: {str(e)}")
        return jsonify({
            "message": str(e),
            "status": "error"
        }), 500

# Analytics
@app.route('/api/analytics/dashboard', methods=['GET'])
@token_required
@swag_from({
    'tags': ['Analytics'],
    'description': 'Get dashboard data for the influencer',
    'responses': {
        '200': {
            'description': 'Dashboard data'
        },
        '500': {'description': 'Internal server error'}
    }
})
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
        
    port = int(os.getenv("PORT", 8081))
    app.run(host="0.0.0.0", port=port)