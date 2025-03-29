from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
from chatbot import Chatbot
from supabase import create_client, Client
import os
from config import (
    CLOUDINARY_CLOUD_NAME,
    CLOUDINARY_API_KEY,
    CLOUDINARY_API_SECRET,
    SUPABASE_URL,
    SUPABASE_KEY
)

app = Flask(__name__)
chatbot = Chatbot()

# Initialize Cloudinary
cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET
)

# Initialize Supabase
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Welcome to the Influencer Chatbot API!"})

@app.route("/chat", methods=["POST"])
def chat():
    data = request.json
    user_input = data.get("message", "")
    influencer_id = data.get("influencer_id", "default")

    if not user_input:
        return jsonify({"error": "No message provided"}), 400

    response = chatbot.get_response(user_input, influencer_id)
    avatar_url = get_influencer_avatar(influencer_id) or "https://res.cloudinary.com/demo/image/upload/default-avatar.png"

    return jsonify({"response": response, "avatar_url": avatar_url})

@app.route("/upload-avatar", methods=["POST"])
def upload_avatar():
    if "image" not in request.files:
        return jsonify({"error": "No image provided"}), 400

    file = request.files["image"]
    influencer_id = request.form.get("influencer_id")
    
    if not influencer_id:
        return jsonify({"error": "Influencer ID is required"}), 400

    filename = secure_filename(file.filename)

    # Upload to Cloudinary
    upload_result = cloudinary.uploader.upload(file, folder="avatars")
    avatar_url = upload_result.get("secure_url")

    # Update avatar in Supabase
    try:
        supabase.table("influencers").update({"avatar_url": avatar_url}).eq("id", influencer_id).execute()
        return jsonify({
            "avatar_url": avatar_url,
            "message": "Avatar uploaded and updated successfully"
        })
    except Exception as e:
        return jsonify({
            "error": f"Failed to update database: {str(e)}",
            "avatar_url": avatar_url
        }), 500

def get_influencer_avatar(influencer_id: str) -> str:
    """Helper function to get influencer avatar URL from Supabase"""
    try:
        response = supabase.table("influencers").select("avatar_url").eq("id", influencer_id).execute()
        if response.data and len(response.data) > 0:
            return response.data[0].get("avatar_url", "")
        return ""
    except Exception:
        return ""

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)