import requests
from langchain_openai import ChatOpenAI
from config import OPENAI_API_KEY, APIFY_API_KEY, HEYGEN_API_KEY, ELEVEN_LABS_API_KEY
import time
import tempfile
import base64
import os
import json

class Chatbot:
    def __init__(self, db=None):
        self.llm = ChatOpenAI(openai_api_key=OPENAI_API_KEY)
        self.heygen_api_key = HEYGEN_API_KEY
        self.apify_api_key = APIFY_API_KEY
        self.eleven_labs_api_key = ELEVEN_LABS_API_KEY
        self.db = db  # Database instance for retrieving bio and history

    def get_product_recommendations(self, query, influencer_id):
        """Fetch product recommendations from Amazon using Apify API."""
        apify_url = "https://api.apify.com/v2/acts/michodemic~amazon-category-scrapper/run-sync-get-dataset"
        params = {
            "token": self.apify_api_key,
            "queries": [query],
            "maxResults": 5
        }
        
        try:
            response = requests.post(apify_url, json=params)
            
            if response.status_code == 200:
                products = response.json()
                return self.format_products(products, influencer_id)
            else:
                return "Sorry, I couldn't fetch product recommendations at the moment."
        except Exception as e:
            return f"Error fetching product recommendations: {str(e)}"

    def format_products(self, products, influencer_id):
        """Format product recommendations and append influencer affiliate link."""
        formatted_products = []
        
        for product in products.get("items", [])[:5]:  # Limit to 5 items
            title = product.get("title", "No title")
            price = product.get("price", "N/A")
            url = product.get("url", "#")
            image_url = product.get("image_url", "")
            
            # Append affiliate tracking
            affiliate_url = f"{url}?tag={influencer_id}"
            
            product_info = f"🛒 {title} - {price}\n"
            if image_url:
                product_info += f"📷 [Image]({image_url})\n"
            product_info += f"🔗 [Buy Now]({affiliate_url})"
            
            formatted_products.append(product_info)

        if formatted_products:
            recommendations = "\n\n".join(formatted_products)
            return f"### Recommended Products\n\n{recommendations}"
        else:
            return "No products found."

    def analyze_message_for_product_intent(self, message):
        """Determine if the message indicates product interest and extract query."""
        # Keywords that suggest product interest
        product_keywords = ["recommend", "suggest", "buy", "purchase", "product", 
                           "shopping", "shop", "get", "want", "need", "looking for"]
        
        message_lower = message.lower()
        
        # Check if any keyword is in the message
        for keyword in product_keywords:
            if keyword in message_lower:
                # Extract potential product query - everything after the keyword
                query_start = message_lower.find(keyword) + len(keyword)
                query = message[query_start:].strip()
                
                # If query is too short, use the whole message
                if len(query) < 3:
                    query = message
                
                return True, query
                
        return False, ""
    
    def analyze_message_for_bio_intent(self, message):
        """Determine if the message is asking about the influencer."""
        bio_keywords = ["about you", "who are you", "tell me about yourself", 
                        "your background", "your story", "your history", "your profile"]
        
        message_lower = message.lower()
        
        for keyword in bio_keywords:
            if keyword in message_lower:
                return True
                
        return False

    def get_chat_response(self, message, influencer_id=None, fan_id=None, influencer_name=None):
        """Generate a conversational response with context."""
        context = ""
        
        # Add influencer bio if available and relevant
        if self.db and influencer_id and self.analyze_message_for_bio_intent(message):
            influencer = self.db.get_influencer(influencer_id)
            if influencer and influencer.get("bio"):
                context += f"Influencer Bio: {influencer['bio']}\n\n"
        
        # Add chat history for context if fan_id is provided
        if self.db and influencer_id and fan_id:
            chat_history = self.db.get_chat_history(influencer_id, fan_id, limit=5)
            if chat_history:
                context += "Recent conversation history:\n"
                # Reverse to get chronological order
                for chat in reversed(chat_history):
                    context += f"User: {chat['user_message']}\n"
                    context += f"You: {chat['bot_response']}\n"
                context += "\n"
        
        prompt = f"""You are a friendly, helpful AI assistant for an influencer{' named ' + influencer_name if influencer_name else ''}. 
        {context}
        Respond to the following message in a conversational, engaging way:
        
        User message: {message}
        
        Keep your response concise (2-3 sentences max) and personable."""
        
        response = self.llm.invoke(prompt)
        return response.content if hasattr(response, 'content') else str(response)

    def get_response(self, message, influencer_id, fan_id=None, influencer_name=None, voice_mode=False, voice_id=None):
        """Generate a response with optional product recommendations and voice."""
        # Check if the message indicates product interest
        is_product_query, product_query = self.analyze_message_for_product_intent(message)
        
        # Generate conversational response
        chat_response = self.get_chat_response(message, influencer_id, fan_id, influencer_name)
        
        # If product interest is detected, add product recommendations
        if is_product_query:
            product_recommendations = self.get_product_recommendations(product_query, influencer_id)
            full_response = f"{chat_response}\n\n{product_recommendations}"
        else:
            full_response = chat_response
        
        # Generate video avatar for the chat response only (not including product recommendations)
        video_url = self.generate_avatar_video(chat_response, influencer_id)
        
        # Generate audio if voice mode is enabled
        audio_url = None
        if voice_mode:
            if voice_id:
                # Use the influencer's cloned voice if available
                audio_url = self.generate_voice_audio(chat_response, voice_id)
            else:
                # Use a default voice if no cloned voice is available
                audio_url = self.generate_voice_audio(chat_response)
        
        return {
            "text": full_response,
            "chat_response": chat_response,  # Just the conversational part
            "video_url": video_url,
            "audio_url": audio_url,
            "has_product_recommendations": is_product_query,
            "voice_mode": voice_mode
        }
    
    def generate_avatar_video(self, text, avatar_id):
        """Generate avatar video using HeyGen API v2"""
        headers = {
            "X-Api-Key": self.heygen_api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Ensure text isn't too long for video generation
        if len(text) > 1000:  # HeyGen v2 has 1500 char limit but we'll use 1000 to be safe
            text = text[:997] + "..."
            
        # Prepare payload according to v2 API
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
                        "input_text": text,
                        "voice_id": "1bd001e7e50f421d891986aad5158bc8",  # Default voice
                        "speed": 1.0
                    }
                }
            ],
            "dimension": {
                "width": 1280,
                "height": 720
            }
        }
        
        try:
            # Generate video
            response = requests.post(
                "https://api.heygen.com/v2/video/generate",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                video_data = response.json()
                video_id = video_data.get("data", {}).get("video_id")
                
                if not video_id:
                    print(f"Error: No video_id in response: {response.text}")
                    return ""
                
                # Now we need to check the video status and wait for it to complete
                # We'll implement a simple polling mechanism with timeout
                max_attempts = 20
                attempt = 0
                
                while attempt < max_attempts:
                    # Check video status
                    status_response = requests.get(
                        f"https://api.heygen.com/v1/video_status.get?video_id={video_id}",
                        headers=headers
                    )
                    
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        status = status_data.get("data", {}).get("status")
                        
                        if status == "completed":
                            # Video is ready
                            return status_data.get("data", {}).get("video_url", "")
                        elif status == "failed":
                            print(f"Video generation failed: {status_data}")
                            return ""
                    
                    # Wait before checking again
                    time.sleep(3)  # Wait 3 seconds between checks
                    attempt += 1
                
                # If we reached here, the video wasn't ready within our timeout
                print(f"Video generation timed out after {max_attempts} attempts")
                return f"https://api.heygen.com/v1/video_status.get?video_id={video_id}"  # Return ID for manual checking
            else:
                print(f"Error generating video: {response.status_code} - {response.text}")
                return ""
        except Exception as e:
            print(f"Exception generating video: {str(e)}")
            return ""
    
    def generate_voice_audio(self, text, voice_id=None):
        """Generate audio using ElevenLabs API with option for cloned voice"""
        if not self.eleven_labs_api_key:
            print("ElevenLabs API key not configured")
            return None
            
        # If no specific voice ID is provided, use default
        if not voice_id:
            voice_id = "21m00Tcm4TlvDq8ikWAM"  # Default ElevenLabs voice
            
        headers = {
            "xi-api-key": self.eleven_labs_api_key,
            "Content-Type": "application/json"
        }
        
        payload = {
            "text": text,
            "model_id": "eleven_monolingual_v1",
            "voice_settings": {
                "stability": 0.5,
                "similarity_boost": 0.75
            }
        }
        
        try:
            response = requests.post(
                f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                # Create a temporary file to store the audio
                with tempfile.NamedTemporaryFile(delete=False, suffix='.mp3') as temp_file:
                    temp_file.write(response.content)
                    temp_filename = temp_file.name
                
                # Read file and convert to base64
                with open(temp_filename, 'rb') as audio_file:
                    audio_content = audio_file.read()
                    audio_base64 = base64.b64encode(audio_content).decode('utf-8')
                
                # Clean up
                os.remove(temp_filename)
                
                return f"data:audio/mpeg;base64,{audio_base64}"
            else:
                print(f"Error generating audio: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"Exception generating audio: {str(e)}")
            return None
    
    def create_cloned_voice(self, name, audio_files, description=""):
        """Create a cloned voice using ElevenLabs Voice Clone API"""
        if not self.eleven_labs_api_key:
            print("ElevenLabs API key not configured")
            return None, "ElevenLabs API key not configured"
            
        headers = {
            "xi-api-key": self.eleven_labs_api_key
        }
        
        # ElevenLabs requires at least 1 minute of clear audio
        # We'll assume the provided audio files meet this requirement
        
        # Prepare the form data
        form_data = {
            "name": name,
            "description": description
        }
        
        files = []
        for i, audio_file in enumerate(audio_files):
            # audio_file should be bytes or a file path
            if isinstance(audio_file, bytes):
                files.append(
                    ('files', (f'sample_{i}.mp3', audio_file, 'audio/mpeg'))
                )
            else:
                files.append(
                    ('files', (f'sample_{i}.mp3', open(audio_file, 'rb'), 'audio/mpeg'))
                )
        
        try:
            response = requests.post(
                "https://api.elevenlabs.io/v1/voices/add",
                headers=headers,
                data=form_data,
                files=files
            )
            
            if response.status_code == 200:
                result = response.json()
                voice_id = result.get("voice_id")
                return voice_id, "Voice created successfully"
            else:
                error_message = f"Error creating voice: {response.status_code} - {response.text}"
                print(error_message)
                return None, error_message
        except Exception as e:
            error_message = f"Exception creating voice: {str(e)}"
            print(error_message)
            return None, error_message
        finally:
            # Close file handles if we opened any
            for file_tuple in files:
                if not isinstance(file_tuple[1][1], bytes):
                    file_tuple[1][1].close()
    
    def get_available_voices(self):
        """Get list of available voices from ElevenLabs"""
        if not self.eleven_labs_api_key:
            print("ElevenLabs API key not configured")
            return []
            
        headers = {
            "xi-api-key": self.eleven_labs_api_key
        }
        
        try:
            response = requests.get(
                "https://api.elevenlabs.io/v1/voices",
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                voices = result.get("voices", [])
                
                # Format voice data
                formatted_voices = [
                    {
                        "voice_id": voice.get("voice_id"),
                        "name": voice.get("name"),
                        "preview_url": voice.get("preview_url"),
                        "description": voice.get("description", "")
                    }
                    for voice in voices
                ]
                
                return formatted_voices
            else:
                print(f"Error getting voices: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            print(f"Exception getting voices: {str(e)}")
            return []
    
    def transcribe_audio(self, audio_file):
        """Transcribe audio file to text using OpenAI Whisper API"""
        if not OPENAI_API_KEY:
            print("OpenAI API key not configured")
            return None
            
        try:
            # Use temporary file if audio_file is bytes
            if isinstance(audio_file, bytes):
                with tempfile.NamedTemporaryFile(delete=False, suffix='.mp3') as temp_file:
                    temp_file.write(audio_file)
                    audio_path = temp_file.name
            else:
                audio_path = audio_file
                
            files = {'file': open(audio_path, 'rb')}
            headers = {'Authorization': f'Bearer {OPENAI_API_KEY}'}
            
            response = requests.post(
                'https://api.openai.com/v1/audio/transcriptions',
                headers=headers,
                files=files,
                data={'model': 'whisper-1'}
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('text')
            else:
                print(f"Error transcribing audio: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"Exception transcribing audio: {str(e)}")
            return None
        finally:
            # Clean up temporary file if we created one
            if isinstance(audio_file, bytes) and 'audio_path' in locals():
                import os
                os.unlink(audio_path)