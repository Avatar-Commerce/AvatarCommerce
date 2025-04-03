from flask import Flask, request, jsonify
from supabase import create_client, Client
import requests
import os
from config import SUPABASE_URL, SUPABASE_KEY, HEYGEN_API_KEY
from flasgger import Swagger, swag_from
from flask_cors import CORS
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps  
from database import Database
import hashlib
import uuid


app = Flask(__name__)
CORS(app) 
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', '7e7b638618760aeb74cf909c0733787a64388d307c68f67e9058e9492f7fad69') 
app.config["DEBUG"] = True 

# Configure Swagger properly
app.config['SWAGGER'] = {
    'title': 'Influencer Chatbot API',
    'uiversion': 3,
    'specs_route': '/swagger/',
    'headers': [],
    'specs': [
        {
            'endpoint': 'apispec',
            'route': '/apispec.json',
            'rule_filter': lambda rule: True,
            'model_filter': lambda tag: True,
        }
    ],
}

swagger_template = {
    "info": {
        "title": "Influencer Chatbot API",
        "description": "API for managing influencer avatars and video generation",
        "version": "1.0.0",
        "contact": {
            "email": "your-email@example.com"
        },
    },
    "schemes": ["http", "https"],
    "tags": [
        {
            "name": "Avatars",
            "description": "Operations with digital avatars"
        },
        {
            "name": "Chat",
            "description": "Video generation from chat"
        }
    ]
}

swagger = Swagger(app, template=swagger_template)

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
HEYGEN_API_URL = "https://api.heygen.com/v1"

db = Database()

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = db.get_influencer_by_username(data['username'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'description': 'Register a new user',
    'consumes': ['application/json'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {
                        'type': 'string',
                        'example': 'newuser'
                    },
                    'email': {
                        'type': 'string',
                        'example': 'user@example.com'
                    },
                    'password': {
                        'type': 'string',
                        'example': 'securepassword123'
                    }
                },
                'required': ['username', 'email', 'password']
            }
        }
    ],
    'responses': {
        '201': {
            'description': 'User created successfully',
            'examples': {
                'application/json': {
                    'message': 'User created successfully',
                    'user': {
                        'username': 'newuser',
                        'email': 'user@example.com'
                    }
                }
            }
        },
        '400': {
            'description': 'Username or email already exists'
        },
        '500': {
            'description': 'Internal server error'
        }
    }
})
def register():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    # Hash the password (use bcrypt or hashlib)
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Check if the username or email already exists
    if db.get_influencer_by_username(username):
        return jsonify({"message": "Username already exists"}), 400
    if db.get_influencer_by_email(email):
        return jsonify({"message": "Email already exists"}), 400

    # Create user with correct parameter format
    influencer_data = {
        "id": str(uuid.uuid4()),  # Ensure you import uuid at the top
        "username": username,
        "email": email,
        "password_hash": password_hash
    }

    new_influencer = db.create_influencer(influencer_data)
    if not new_influencer:
        return jsonify({"message": "Failed to create influencer"}), 500

    return jsonify({"message": "Registration successful", "user": new_influencer}), 201

@app.route('/login', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'description': 'Login user and get JWT token',
    'consumes': ['application/json'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {
                        'type': 'string',
                        'example': 'existinguser'
                    },
                    'password': {
                        'type': 'string',
                        'example': 'securepassword123'
                    }
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        '200': {
            'description': 'Login successful',
            'examples': {
                'application/json': {
                    'token': 'jwt.token.here',
                    'username': 'existinguser'
                }
            }
        },
        '401': {
            'description': 'Invalid credentials'
        },
        '500': {
            'description': 'Internal server error'
        }
    }
})
def login():
    try:
        # Get JSON data from request
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        # Fetch user from database
        influencer = db.get_influencer_by_username(username)

        if not influencer:
            return jsonify({"error": "Invalid username or password"}), 401

        # Hash the input password for comparison
        hashed_input_password = hashlib.sha256(password.encode()).hexdigest()

        # Compare hashed passwords
        if influencer["password_hash"] != hashed_input_password:
            return jsonify({"error": "Invalid username or password"}), 401

        # Generate a session token (UUID for now, use JWT in production)
        session_token = str(uuid.uuid4())

        return jsonify({
            "message": "Login successful",
            "user": {
                "id": influencer["id"],
                "username": influencer["username"],
                "email": influencer["email"],
                "avatar_id": influencer.get("heygen_avatar_id"),
                "token": session_token  # Replace with JWT in production
            }
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/create-avatar', methods=['POST'])
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
        },
        {
            'name': 'influencer_id',
            'in': 'formData',
            'type': 'string',
            'required': True,
            'description': 'Unique influencer identifier'
        }
    ],
    'responses': {
        '200': {
            'description': 'Avatar created successfully',
            'examples': {
                'application/json': {
                    'avatar_id': 'avatar_123',
                    'message': 'Digital twin created successfully'
                }
            }
        },
        '400': {
            'description': 'Invalid input'
        },
        '500': {
            'description': 'Internal server error'
        }
    }
})
def create_avatar():
    """Create HeyGen avatar from uploaded media"""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    influencer_id = request.form.get("influencer_id")
    if not influencer_id:
        return jsonify({"error": "influencer_id is required"}), 400

    file = request.files['file']
    
    try:
        # 1. Upload original file to Supabase Storage
        file_path = f"avatars/original_{influencer_id}_{file.filename}"
        supabase.storage.from_("influencer_assets").upload(file_path, file.read())

        # 2. Send to HeyGen to create digital twin
        headers = {"X-Api-Key": HEYGEN_API_KEY}
        response = requests.post(
            f"{HEYGEN_API_URL}/avatars.create",
            files={"media": file.stream},
            data={"name": f"influencer_{influencer_id}"},
            headers=headers
        )

        if response.status_code != 201:
            return jsonify({"error": "Avatar creation failed"}), 500

        avatar_id = response.json()["avatar_id"]

        # 3. Store HeyGen avatar ID in database
        supabase.table("influencers").upsert({
            "id": influencer_id,
            "heygen_avatar_id": avatar_id,
            "original_asset_path": file_path
        }).execute()

        return jsonify({
            "avatar_id": avatar_id,
            "message": "Digital twin created successfully",
            "asset_path": file_path
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/chat', methods=['POST'])
@swag_from({
    'tags': ['Chat'],
    'description': 'Generate video response using HeyGen avatar',
    'consumes': ['application/json'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                        'example': 'Hello world!'
                    },
                    'influencer_id': {
                        'type': 'string',
                        'example': 'inf_123'
                    }
                },
                'required': ['message', 'influencer_id']
            }
        }
    ],
    'responses': {
        '200': {
            'description': 'Video generated successfully',
            'examples': {
                'application/json': {
                    'text': 'Generated response text',
                    'video_url': 'https://example.com/video.mp4'
                }
            }
        },
        '400': {
            'description': 'Invalid input'
        },
        '500': {
            'description': 'Internal server error'
        }
    }
})
def chat():
    """Generate video response using HeyGen avatar"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request must be JSON"}), 400
    
    user_input = data.get("message", "")
    influencer_id = data.get("influencer_id")
    
    if not user_input or not influencer_id:
        return jsonify({"error": "message and influencer_id are required"}), 400

    try:
        # 1. Get text response from LLM
        text_response = "This would come from your Chatbot class"

        # 2. Generate talking avatar video
        avatar_data = supabase.table("influencers")\
            .select("heygen_avatar_id")\
            .eq("id", influencer_id)\
            .execute().data[0]

        headers = {"X-Api-Key": HEYGEN_API_KEY}
        video_response = requests.post(
            f"{HEYGEN_API_URL}/videos.generate",
            json={
                "avatar_id": avatar_data["heygen_avatar_id"],
                "text": text_response,
                "voice_id": "default_voice"
            },
            headers=headers
        )

        return jsonify({
            "text": text_response,
            "video_url": video_response.json()["video_url"]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8081)) 
    app.run(host="0.0.0.0", port=port)