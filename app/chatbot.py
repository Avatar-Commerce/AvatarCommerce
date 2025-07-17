import os
import openai
import json
import requests
import time
import tempfile
import base64
from datetime import datetime
from typing import Dict, List, Optional
from sentence_transformers import SentenceTransformer
import numpy as np

from config import Config

# Try to import RAGProcessor if available
try:
    from rag_processor import RAGProcessor
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    print("⚠️ RAGProcessor not available. Knowledge features will be limited.")

class Chatbot:
    def __init__(self, db=None):
        self.client = openai.OpenAI(api_key=Config.OPENAI_API_KEY)
        self.embedding_model = None  # Will be loaded when needed
        self.heygen_api_key = Config.HEYGEN_API_KEY
        self.eleven_labs_api_key = Config.ELEVEN_LABS_API_KEY
        self.db = db
        
    def get_embedding_model(self):
        """Lazy load the embedding model to save memory"""
        if self.embedding_model is None:
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        return self.embedding_model

    def enhance_response_with_knowledge(self, user_message: str, influencer_data: Dict) -> str:
        """Enhanced response with knowledge base integration"""
        if not RAG_AVAILABLE:
            return ""
        
        try:
            # Query knowledge base
            rag_processor = RAGProcessor(
                supabase_url=os.getenv("SUPABASE_URL"),
                supabase_key=os.getenv("SUPABASE_SERVICE_KEY"),
                openai_api_key=os.getenv("OPENAI_API_KEY")
            )
            
            relevant_chunks = rag_processor.query_knowledge(
                influencer_id=influencer_data['id'],
                query=user_message,
                top_k=3
            )
            
            # Build context from relevant chunks
            knowledge_context = ""
            if relevant_chunks:
                knowledge_context = "\n\nAdditional context from my knowledge base:\n"
                for chunk in relevant_chunks:
                    if chunk['similarity'] > 0.7:  # Only use highly relevant chunks
                        knowledge_context += f"- {chunk['chunk_text'][:200]}...\n"
            
            return knowledge_context
        except Exception as e:
            print(f"Knowledge enhancement error: {e}")
            return ""
    
    def get_chat_response_with_knowledge(self, message, influencer_id=None, session_id=None, 
                                       influencer_name=None, db=None):
        """Generate a conversational response using RAG with user's knowledge base"""
        try:
            # Get relevant knowledge from user's knowledge base
            knowledge_context = ""
            personal_context = ""
            
            if db and influencer_id:
                # Get personal information
                try:
                    personal_info = db.get_personal_knowledge(influencer_id)
                    if personal_info:
                        personal_parts = []
                        if personal_info.get('bio'):
                            personal_parts.append(f"About you: {personal_info['bio']}")
                        if personal_info.get('expertise'):
                            personal_parts.append(f"Expertise: {personal_info['expertise']}")
                        if personal_info.get('personality'):
                            personal_parts.append(f"Communication style: {personal_info['personality']}")
                        
                        if personal_parts:
                            personal_context = f"\n\nPersonal information about you:\n" + "\n".join(personal_parts)
                except Exception as e:
                    print(f"Error getting personal info: {e}")
                
                # Try to get knowledge from uploaded documents
                if RAG_AVAILABLE:
                    try:
                        # Generate embedding for the query
                        model = self.get_embedding_model()
                        query_embedding = model.encode([message])[0].tolist()
                        
                        # Search knowledge base
                        knowledge_results = db.search_knowledge_base(influencer_id, query_embedding, limit=3)
                        
                        # Build knowledge context
                        if knowledge_results:
                            relevant_chunks = []
                            for result in knowledge_results:
                                if result['similarity'] > 0.3:  # Only include relevant results
                                    relevant_chunks.append(f"From {result['document_name']}: {result['text']}")
                            
                            if relevant_chunks:
                                knowledge_context = f"\n\nRelevant information from your knowledge base:\n" + "\n".join(relevant_chunks)
                    except Exception as e:
                        print(f"Knowledge search error: {e}")
            
            # Create enhanced system prompt with knowledge
            system_prompt = self._build_enhanced_system_prompt(
                influencer_name, personal_context, knowledge_context
            )
            
            # Generate response using OpenAI
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message}
                ],
                max_tokens=500,
                temperature=0.7
            )
            
            ai_response = response.choices[0].message.content.strip()
            
            # Check if this is a product-related query and add recommendations if needed
            if self._is_product_query(message):
                product_recommendations = self.get_product_recommendations(message, influencer_id)
                if product_recommendations:
                    ai_response += f"\n\n{product_recommendations}"
            
            return ai_response
            
        except Exception as e:
            print(f"❌ Enhanced chat response error: {str(e)}")
            return self.get_fallback_response(message, influencer_name)
    
    def _build_enhanced_system_prompt(self, influencer_name, personal_context, knowledge_context):
        """Build an enhanced system prompt with personal and knowledge context"""
        base_name = influencer_name or "the influencer"
        
        system_prompt = f"""You are an AI assistant representing {base_name}. You help users by providing helpful, engaging, and personalized responses.

CORE INSTRUCTIONS:
- Be conversational, friendly, and authentic
- Provide helpful and accurate information
- When relevant, recommend products that would genuinely help the user
- Stay true to the personality and values described below
- Use the knowledge base information when it's relevant to the user's question
- If you don't know something specific, be honest about it

{personal_context}

{knowledge_context}

RESPONSE GUIDELINES:
- Keep responses concise but informative (2-4 sentences usually)
- Be helpful and solution-oriented
- Use a natural, conversational tone
- Include product recommendations only when they genuinely help answer the user's question
- Reference your knowledge when it's relevant to provide better answers

Remember: You are representing {base_name}, so respond as if you are them, using their knowledge and personality."""

        return system_prompt
    
    def _is_product_query(self, message):
        """Determine if the message is asking for product recommendations"""
        product_keywords = [
            'recommend', 'suggestion', 'what should i buy', 'best product', 
            'looking for', 'need help choosing', 'what do you think about',
            'review', 'opinion', 'should i get', 'worth buying', 'alternatives'
        ]
        
        message_lower = message.lower()
        return any(keyword in message_lower for keyword in product_keywords)
    
    def get_fallback_response(self, message, influencer_name=None):
        """Generate a fallback response when the main system fails"""
        name = influencer_name or "I"
        
        fallback_responses = [
            f"Thanks for your message! {name} would love to help you with that. Could you tell me a bit more about what you're looking for?",
            f"That's a great question! Let me think about the best way to help you with that.",
            f"I appreciate you reaching out! {name} always enjoys connecting with followers. What specific information can I help you find?",
            f"Thanks for asking! I want to give you the most helpful response possible. Could you provide a bit more detail about what you need?"
        ]
        
        import random
        return random.choice(fallback_responses)
    
    def get_product_recommendations(self, query: str, influencer_id: str) -> str:
        """Generate AI-based product recommendations"""
        try:
            prompt = f"""You are helping an influencer recommend products related to: {query}

            Generate 3 realistic, specific product recommendations that would be relevant.
            For each product, provide:
            - A specific product name
            - A realistic price range
            - A brief compelling description
            - Why it's relevant to the query

            Format as a clean, engaging product list that feels natural in a conversation.
            """
            
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a helpful product recommendation assistant."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=400,
                temperature=0.7
            )
            
            ai_response = response.choices[0].message.content.strip()
            
            # Get influencer's affiliate links for formatting
            if self.db:
                try:
                    affiliate_links = self.db.get_affiliate_links(influencer_id)
                    if affiliate_links:
                        primary_link = next((link for link in affiliate_links if link.get('is_primary')), affiliate_links[0])
                        platform_name = primary_link.get('platform', '').replace('_', ' ').title()
                        ai_response += f"\n\n💡 *I can help you find these products on {platform_name} - just let me know what interests you!*"
                except:
                    pass
            
            return ai_response
            
        except Exception as e:
            print(f"Product recommendation error: {str(e)}")
            return f"I'd be happy to help you find products related to {query}! Let me know what specific features or budget you have in mind."
    
    def generate_video_response(self, text_response, avatar_id, voice_id=None):
        """Generate video response using HeyGen with enhanced error handling"""
        if not avatar_id or not text_response:
            print("❌ Missing avatar_id or text_response for video generation")
            return ""
        
        try:
            print(f"🎬 Generating video for avatar {avatar_id}")
            print(f"📝 Text length: {len(text_response)} characters")
            
            # Prepare the request
            headers = {
                "X-Api-Key": self.heygen_api_key,
                "Content-Type": "application/json"
            }
            
            # Clean and limit text for video generation
            video_text = self._prepare_text_for_video(text_response)
            
            payload = {
                "video_inputs": [{
                    "character": {
                        "type": "avatar",
                        "avatar_id": avatar_id,
                        "avatar_style": "normal"
                    },
                    "voice": {
                        "type": "text",
                        "input_text": video_text,
                        "voice_id": voice_id or "2d5b0e6cf36f460aa7fc47e3eee4ba54"
                    }
                }],
                "aspect_ratio": "16:9",
                "test": False
            }
            
            print(f"📤 Sending video generation request...")
            
            # Make the request with timeout
            response = requests.post(
                "https://api.heygen.com/v2/video/generate",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            print(f"📡 Video generation response status: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    print(f"📋 Video generation response: {result}")
                    
                    if not result.get('error') and result.get('data'):
                        video_id = result['data'].get('video_id')
                        if video_id:
                            print(f"✅ Video generation started, ID: {video_id}")
                            # Poll for completion
                            return self._poll_video_status(video_id, headers, max_attempts=25)
                        else:
                            print("❌ No video_id in response")
                            return ""
                    else:
                        print(f"❌ Video generation failed: {result.get('error', 'Unknown error')}")
                        return ""
                        
                except json.JSONDecodeError as e:
                    print(f"❌ Failed to parse JSON: {e}")
                    print(f"Raw response: {response.text}")
                    return ""
                    
            else:
                print(f"❌ Request failed with status {response.status_code}")
                print(f"Response: {response.text}")
                return ""
                
        except requests.exceptions.Timeout:
            print("⏱️  Video generation request timed out")
            return ""
        except requests.exceptions.RequestException as e:
            print(f"🌐 Network error during video generation: {str(e)}")
            return ""
        except Exception as e:
            print(f"❌ Unexpected error in video generation: {str(e)}")
            return ""
    
    def generate_avatar_video_with_voice(self, text_response, influencer_id, voice_id):
        """Generate avatar video with specific voice"""
        if not self.db:
            print("❌ No database connection for avatar video generation")
            return ""
        
        # Get influencer data
        influencer = self.db.get_influencer(influencer_id)
        if not influencer:
            print(f"❌ Influencer not found: {influencer_id}")
            return ""
        
        avatar_id = influencer.get('heygen_avatar_id')
        if not avatar_id:
            print(f"❌ No avatar ID found for influencer: {influencer_id}")
            return ""
        
        return self.generate_video_response(text_response, avatar_id, voice_id)
    
    def _prepare_text_for_video(self, text):
        """Prepare text for video generation by cleaning and limiting length"""
        # Remove product recommendation sections for cleaner video
        lines = text.split('\n')
        clean_lines = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('🛍️') and not line.startswith('**Product'):
                clean_lines.append(line)
        
        clean_text = ' '.join(clean_lines)
        
        # Limit to reasonable length for video (roughly 30-45 seconds of speech)
        if len(clean_text) > 400:
            sentences = clean_text.split('. ')
            truncated = '. '.join(sentences[:3])
            if not truncated.endswith('.'):
                truncated += '.'
            return truncated
        
        return clean_text
    
    def _poll_video_status(self, video_id, headers, max_attempts=25):
        """Poll video status with improved timing and error handling"""
        attempt = 0
        base_wait_time = 3
        
        print(f"🔄 Starting to poll video status for ID: {video_id}")
        
        while attempt < max_attempts:
            try:
                status_response = requests.get(
                    f"https://api.heygen.com/v1/video_status.get?video_id={video_id}",
                    headers=headers,
                    timeout=15
                )
                
                if status_response.status_code == 200:
                    try:
                        status_data = status_response.json()
                        
                        if "data" in status_data:
                            data = status_data["data"]
                            status = data.get("status", "unknown")
                            video_url = data.get("video_url", "")
                            
                            print(f"🎬 Attempt {attempt + 1}/{max_attempts}: Video status: {status}")
                            
                            if status == "completed":
                                if video_url and video_url.strip():
                                    print(f"✅ Video generation completed: {video_url}")
                                    return video_url
                                else:
                                    if attempt < max_attempts - 5:  # Give it more chances
                                        print("⏳ Video completed but no URL yet, continuing to poll...")
                                    else:
                                        print("❌ Video completed but no URL provided")
                                        return ""
                                        
                            elif status == "failed":
                                error_info = data.get("error", "Unknown error")
                                print(f"❌ Video generation failed: {error_info}")
                                return ""
                                
                            elif status in ["processing", "pending", "waiting", "queued"]:
                                print(f"⏳ Video status: {status}, waiting...")
                                
                            else:
                                print(f"❓ Unknown video status: {status}")
                        
                        else:
                            print(f"⚠️  Unexpected response format: {status_data}")
                            
                    except json.JSONDecodeError as e:
                        print(f"❌ Failed to parse status JSON: {e}")
                        
                elif status_response.status_code == 404:
                    print(f"❌ Video ID not found: {video_id}")
                    return ""
                    
                else:
                    print(f"⚠️  Status check failed: {status_response.status_code}")
            
            except Exception as e:
                print(f"❌ Error during status check: {str(e)}")
            
            # Dynamic wait time
            wait_time = base_wait_time + (attempt // 5) * 2
            print(f"⏳ Waiting {wait_time} seconds before next attempt...")
            time.sleep(wait_time)
            attempt += 1
        
        print(f"⏰ Video generation timed out after {max_attempts} attempts")
        return ""

    def get_chat_response(self, message, influencer_id=None, session_id=None, influencer_name=None):
        """Generate a conversational response with context."""
        context = ""
        
        # Add influencer bio if available and relevant
        if self.db and influencer_id:
            influencer = self.db.get_influencer(influencer_id)
            if influencer and influencer.get("bio"):
                context += f"Influencer Bio: {influencer['bio']}\n\n"
        
        # Add chat history for context if session_id is provided
        if self.db and influencer_id and session_id:
            try:
                chat_history = self.db.get_chat_history(influencer_id, session_id, limit=5)
                if chat_history:
                    context += "Recent conversation history:\n"
                    # Reverse to get chronological order
                    for chat in reversed(chat_history):
                        context += f"User: {chat['user_message']}\n"
                        context += f"You: {chat['bot_response']}\n"
                    context += "\n"
            except:
                pass  # Chat history not available
        
        prompt = f"""You are a friendly, helpful AI assistant for an influencer{' named ' + influencer_name if influencer_name else ''}. 
        {context}
        Respond to the following message in a conversational, engaging way:
        
        User message: {message}
        
        Keep your response concise (2-3 sentences max) and personable."""
        
        try:
            # Use OpenAI to generate response
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a helpful AI assistant."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=300,
                temperature=0.7
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            print(f"Chat response error: {e}")
            return self.get_fallback_response(message, influencer_name)
    
    def generate_voice_audio(self, text, voice_id=None):
        """Generate audio using multiple TTS services with robust fallback."""
        # List of TTS services to try
        tts_services = [
            self._generate_elevenlabs_audio,
            self._generate_google_tts_audio,
            self._generate_default_tts_audio
        ]
        
        # Try each service until successful
        for service in tts_services:
            try:
                audio_url = service(text, voice_id)
                if audio_url:
                    return audio_url
            except Exception as e:
                print(f"TTS service failed: {service.__name__}, Error: {str(e)}")
        
        # If all services fail, return None
        return None
    
    def _generate_elevenlabs_audio(self, text, voice_id=None):
        """Generate audio using ElevenLabs API"""
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
                json=payload,
                timeout=10
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
                try:
                    os.remove(temp_filename)
                except Exception as e:
                    print(f"Warning: Could not remove temporary file: {str(e)}")
                
                return f"data:audio/mpeg;base64,{audio_base64}"
            
            print(f"ElevenLabs API error: {response.status_code} - {response.text}")
            return None
        
        except Exception as e:
            print(f"ElevenLabs audio generation error: {str(e)}")
            return None

    def _generate_google_tts_audio(self, text, voice_id=None):
        """Generate audio using Google Text-to-Speech as a fallback"""
        try:
            from gtts import gTTS
            import io
            
            # Create a text-to-speech object
            tts = gTTS(text=text, lang='en', slow=False)
            
            # Save to a bytes buffer
            mp3_fp = io.BytesIO()
            tts.write_to_fp(mp3_fp)
            mp3_fp.seek(0)
            
            # Convert to base64
            audio_content = mp3_fp.read()
            audio_base64 = base64.b64encode(audio_content).decode('utf-8')
            
            return f"data:audio/mpeg;base64,{audio_base64}"
        
        except ImportError:
            print("gTTS library not installed. Install with: pip install gtts")
            return None
        except Exception as e:
            print(f"Google TTS error: {str(e)}")
            return None

    def _generate_default_tts_audio(self, text, voice_id=None):
        """Generate a basic synthetic audio as last resort"""
        try:
            # Simple synthetic audio generation
            import numpy as np
            from scipy.io import wavfile
            import io
            
            # Generate a simple tone-based audio
            duration = 2  # seconds
            sample_rate = 44100
            t = np.linspace(0, duration, int(sample_rate * duration), False)
            
            # Create a simple tone representing speech
            audio = np.sin(2 * np.pi * 440 * t) * 0.3
            
            # Convert to 16-bit PCM
            audio = (audio * 32767).astype(np.int16)
            
            # Save to bytes buffer
            wav_buffer = io.BytesIO()
            wavfile.write(wav_buffer, sample_rate, audio)
            wav_buffer.seek(0)
            
            # Convert to base64
            audio_content = wav_buffer.read()
            audio_base64 = base64.b64encode(audio_content).decode('utf-8')
            
            return f"data:audio/wav;base64,{audio_base64}"
        
        except Exception as e:
            print(f"Default audio generation error: {str(e)}")
            return None