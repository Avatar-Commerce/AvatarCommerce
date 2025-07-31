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

# Import the new affiliate service
try:
    from affiliate_service import AffiliateService, ProductRecommendationFormatter
    AFFILIATE_AVAILABLE = True
except ImportError:
    AFFILIATE_AVAILABLE = False
    print("⚠️ AffiliateService not available. Product recommendations will be limited.")

# Try to import RAGProcessor if available
try:
    from rag_processor import RAGProcessor
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    print("⚠️ RAGProcessor not available. Knowledge features will be limited.")

class EnhancedChatbot:
    def __init__(self, db=None):
        self.client = openai.OpenAI(api_key=Config.OPENAI_API_KEY)
        self.embedding_model = None  # Will be loaded when needed
        self.heygen_api_key = Config.HEYGEN_API_KEY
        self.eleven_labs_api_key = Config.ELEVEN_LABS_API_KEY
        self.db = db
        
        # Initialize affiliate service
        self.affiliate_service = AffiliateService(db) if AFFILIATE_AVAILABLE else None
        
        # Initialize RAG processor for knowledge documents
        if RAG_AVAILABLE and Config.SUPABASE_URL and Config.SUPABASE_KEY:
            self.rag_processor = RAGProcessor(
                Config.SUPABASE_URL, 
                Config.SUPABASE_KEY, 
                Config.OPENAI_API_KEY
            )
        else:
            self.rag_processor = None

    def get_embedding_model(self):
        """Lazy load the embedding model to save memory"""
        if self.embedding_model is None:
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        return self.embedding_model

    def get_chat_response_with_knowledge(self, message, influencer_id=None, session_id=None, 
                                       influencer_name=None, db=None, voice_mode=False):
        """ENHANCED: Chat response with comprehensive knowledge integration"""
        try:
            # Initialize contexts
            knowledge_context = ""
            personal_context = ""
            product_recommendations = ""
            
            if db and influencer_id:
                # ENHANCED: Get comprehensive personal information
                try:
                    personal_info = db.get_personal_knowledge(influencer_id)
                    if personal_info:
                        personal_parts = []
                        if personal_info.get('bio'):
                            personal_parts.append(f"Bio: {personal_info['bio']}")
                        if personal_info.get('expertise'):
                            personal_parts.append(f"Areas of expertise: {personal_info['expertise']}")
                        if personal_info.get('personality'):
                            personal_parts.append(f"Communication style: {personal_info['personality']}")
                        
                        if personal_parts:
                            personal_context = f"\n\nYour personal information:\n" + "\n".join(personal_parts)
                            print(f"✅ Personal context loaded: {len(personal_context)} characters")
                except Exception as e:
                    print(f"Error getting personal info: {e}")
                
                # ENHANCED: Get knowledge from uploaded documents using RAG
                try:
                    if self.rag_processor:
                        # Use RAG processor for semantic search
                        knowledge_results = self.rag_processor.query_knowledge(influencer_id, message, top_k=5)
                        
                        if knowledge_results:
                            relevant_chunks = []
                            for result in knowledge_results:
                                if result['similarity'] > 0.4:  # Adjusted threshold
                                    relevant_chunks.append(f"From {result['filename']}: {result['chunk_text']}")
                            
                            if relevant_chunks:
                                knowledge_context = f"\n\nRelevant information from your knowledge documents:\n" + "\n".join(relevant_chunks)
                                print(f"✅ Knowledge context loaded: {len(knowledge_context)} characters from {len(relevant_chunks)} chunks")
                    else:
                        # Fallback to simpler knowledge search if RAG not available
                        knowledge_results = db.search_knowledge_base(influencer_id, message, limit=3) if hasattr(db, 'search_knowledge_base') else []
                        
                        if knowledge_results:
                            relevant_chunks = []
                            for result in knowledge_results:
                                if result.get('similarity', 0) > 0.3:
                                    document_name = result.get('document_name', 'uploaded document')
                                    text = result.get('text', result.get('chunk_text', ''))
                                    relevant_chunks.append(f"From {document_name}: {text}")
                            
                            if relevant_chunks:
                                knowledge_context = f"\n\nRelevant information from your knowledge base:\n" + "\n".join(relevant_chunks)
                                print(f"✅ Fallback knowledge context loaded: {len(knowledge_context)} characters")
                        
                except Exception as e:
                    print(f"Knowledge search error: {e}")
            
            # Check if this is a product-related query and get recommendations
            if self._is_product_query(message) and self.affiliate_service and influencer_id:
                try:
                    recommendations = self.affiliate_service.get_product_recommendations(
                        query=message,
                        influencer_id=influencer_id,
                        limit=3
                    )
                    
                    if recommendations['products']:
                        product_recommendations = ProductRecommendationFormatter.format_recommendations(
                            recommendations['products']
                        )
                        print(f"✅ Product recommendations loaded: {len(recommendations['products'])} products")
                except Exception as e:
                    print(f"Product recommendation error: {e}")
            
            # Create enhanced system prompt with knowledge and voice considerations
            system_prompt = self._build_enhanced_system_prompt(
                influencer_name, personal_context, knowledge_context, voice_mode
            )
            
            # Generate response using OpenAI
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message}
                ],
                max_tokens=600 if voice_mode else 500,
                temperature=0.7
            )
            
            ai_response = response.choices[0].message.content.strip()
            
            # Add product recommendations if available
            if product_recommendations:
                ai_response += f"\n\n{product_recommendations}"
            
            print(f"✅ AI response generated: {len(ai_response)} characters")
            return ai_response
            
        except Exception as e:
            print(f"❌ Enhanced chat response error: {str(e)}")
            return self.get_fallback_response(message, influencer_name)
    
    def _build_enhanced_system_prompt(self, influencer_name, personal_context, knowledge_context, voice_mode=False):
        """Build an enhanced system prompt with comprehensive knowledge integration"""
        base_name = influencer_name or "the influencer"
        
        voice_instructions = ""
        if voice_mode:
            voice_instructions = """
VOICE RESPONSE GUIDELINES:
- Keep responses conversational and natural for voice output
- Use shorter sentences and clearer pronunciation  
- Avoid complex punctuation that doesn't translate well to speech
- Include natural pauses with commas and periods
- Be more expressive and engaging since this will be spoken
- Limit response to 3-4 sentences for optimal voice delivery
- Use simple, everyday language that sounds natural when spoken
"""
        
        system_prompt = f"""You are an AI assistant representing {base_name}. You help users by providing helpful, engaging, and personalized responses based on your knowledge and expertise.

CORE INSTRUCTIONS:
- Be conversational, friendly, and authentic
- Provide helpful and accurate information based on your knowledge
- When users ask for product recommendations, suggest specific items that would genuinely help
- Stay true to the personality and communication style described below
- Use your knowledge base information when it's relevant to the user's question
- Reference your expertise areas when applicable
- If you don't know something specific, be honest about it
- Be concise but informative (2-4 sentences usually)

{voice_instructions}

{personal_context}

{knowledge_context}

KNOWLEDGE USAGE GUIDELINES:
- When you have relevant information from your knowledge documents, use it naturally in your responses
- Reference specific documents or sources when appropriate
- Combine your personal knowledge with uploaded document information
- If the user's question relates to your expertise areas, leverage that information
- Use your personality traits to guide how you communicate

PRODUCT RECOMMENDATION GUIDELINES:
- Only recommend products when the user explicitly asks for recommendations or mentions needing something
- Be specific and helpful with product suggestions
- Focus on quality and relevance over quantity
- Include brief explanations of why you're recommending specific items
- If you recommend products, use natural language like "I'd suggest..." or "You might like..."
- Base recommendations on your expertise and knowledge when possible

RESPONSE STYLE:
- Use a natural, conversational tone that matches your defined personality
- Be helpful and solution-oriented
- Reference your knowledge and expertise when relevant
- Keep responses engaging and personable
- Show your expertise naturally without being boastful

Remember: You are representing {base_name}, so respond as if you are them, using their knowledge, personality, and expertise to provide the most helpful and authentic response possible."""

        return system_prompt
    
    def _is_product_query(self, message):
        """Enhanced product query detection"""
        product_keywords = [
            'recommend', 'suggestion', 'what should i buy', 'best product', 
            'looking for', 'need help choosing', 'what do you think about',
            'review', 'opinion', 'should i get', 'worth buying', 'alternatives',
            'shopping', 'purchase', 'need to buy', 'want to get', 'help me find',
            'product for', 'good option', 'best choice', 'compare', 'vs',
            'cheap', 'affordable', 'expensive', 'price', 'cost', 'budget',
            'where to buy', 'which brand', 'top rated', 'most popular'
        ]
        
        message_lower = message.lower()
        return any(keyword in message_lower for keyword in product_keywords)

    def generate_speech_to_text(self, audio_file_path: str) -> str:
        """FIXED: Use OpenAI Whisper for speech-to-text conversion with proper file handling"""
        try:
            print(f"🎤 Converting speech to text using OpenAI Whisper...")
            print(f"📁 File path: {audio_file_path}")
            
            # Verify file exists and has content
            if not os.path.exists(audio_file_path):
                print(f"❌ Audio file not found: {audio_file_path}")
                return ""
            
            file_size = os.path.getsize(audio_file_path)
            if file_size == 0:
                print(f"❌ Audio file is empty: {audio_file_path}")
                return ""
            
            print(f"📊 File size: {file_size} bytes")
            
            # FIXED: Open file properly and send to OpenAI Whisper
            with open(audio_file_path, "rb") as audio_file:
                # Set proper filename for OpenAI API
                audio_file.name = audio_file_path
                
                transcript = self.client.audio.transcriptions.create(
                    model="whisper-1",
                    file=audio_file,
                    response_format="text",
                    language="en"  # Specify English for better accuracy
                )
            
            # Handle response format
            transcribed_text = transcript.strip() if isinstance(transcript, str) else transcript.text.strip()
            
            if transcribed_text:
                print(f"✅ Speech-to-text completed: {transcribed_text}")
                return transcribed_text
            else:
                print("❌ No transcription returned from OpenAI")
                return ""
                
        except Exception as e:
            print(f"❌ OpenAI speech-to-text error: {e}")
            
            # Log more details about the error
            if hasattr(e, 'response') and e.response:
                print(f"❌ OpenAI API response: {e.response.status_code} - {e.response.text}")
            
            return ""

    def generate_enhanced_video_response(self, text_response, influencer_id, voice_id=None):
        """Generate video response with enhanced voice integration"""
        if not self.db or not influencer_id:
            print("❌ No database or influencer ID for video generation")
            return ""
        
        try:
            # Get influencer data with avatar and voice info
            influencer = self.db.get_influencer(influencer_id)
            if not influencer:
                print(f"❌ Influencer not found: {influencer_id}")
                return ""
            
            avatar_id = influencer.get('heygen_avatar_id')
            if not avatar_id:
                print(f"❌ No avatar ID found for influencer: {influencer_id}")
                return ""
            
            # FIXED: Use influencer's selected voice or get from their profile
            if not voice_id:
                voice_id = influencer.get('preferred_voice_id') or influencer.get('voice_id') or Config.DEFAULT_VOICE_ID
            
            print(f"🎬 Generating video with avatar: {avatar_id}, voice: {voice_id}")
            
            return self.generate_video_response(text_response, avatar_id, voice_id)
            
        except Exception as e:
            print(f"❌ Enhanced video generation error: {e}")
            return ""

    def generate_audio_response(self, text_response, voice_id=None):
        """ENHANCED: Generate audio-only response using influencer's selected voice"""
        try:
            if not voice_id:
                voice_id = Config.DEFAULT_VOICE_ID
            
            print(f"🔊 Generating audio response with voice: {voice_id}")
            
            # Use OpenAI TTS as primary option since user has OpenAI key
            audio_url = self._generate_openai_tts_audio(text_response, voice_id)
            
            if audio_url:
                return audio_url
            
            # Fallback to ElevenLabs if OpenAI TTS fails and available
            if self.eleven_labs_api_key:
                return self._generate_elevenlabs_audio(text_response, voice_id)
            
            # Final fallback
            return self._generate_fallback_audio(text_response, voice_id)
                
        except Exception as e:
            print(f"❌ Audio response generation error: {e}")
            return None

    def _prepare_text_for_voice(self, text):
        """Prepare text specifically for voice generation"""
        # Remove product recommendation sections for cleaner audio
        lines = text.split('\n')
        clean_lines = []
        
        for line in lines:
            line = line.strip()
            # Skip lines with emojis and formatting that don't work well in TTS
            if line and not line.startswith('🛍️') and not line.startswith('**Product') and not line.startswith('💰'):
                # Clean up markdown formatting for voice
                line = line.replace('**', '').replace('*', '').replace('#', '')
                clean_lines.append(line)
        
        clean_text = '. '.join(clean_lines)
        
        # Limit to reasonable length for voice (roughly 30-45 seconds of speech)
        if len(clean_text) > 400:
            sentences = clean_text.split('. ')
            truncated = '. '.join(sentences[:4])  # More sentences for voice
            if not truncated.endswith('.'):
                truncated += '.'
            return truncated
        
        return clean_text
    
    def generate_video_response(self, text_response, avatar_id, voice_id=None):
        """Generate video response using HeyGen with enhanced error handling"""
        if not avatar_id or not text_response:
            print("❌ Missing avatar_id or text_response for video generation")
            return ""
        
        try:
            print(f"🎬 Generating video for avatar: {avatar_id} with voice: {voice_id}")
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
                        "voice_id": voice_id or Config.DEFAULT_VOICE_ID
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
            print("⏱️ Video generation request timed out")
            return ""
        except requests.exceptions.RequestException as e:
            print(f"🌐 Network error during video generation: {str(e)}")
            return ""
        except Exception as e:
            print(f"❌ Unexpected error in video generation: {str(e)}")
            return ""
    
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
                                    if attempt < max_attempts - 5:
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
                            print(f"⚠️ Unexpected response format: {status_data}")
                            
                    except json.JSONDecodeError as e:
                        print(f"❌ Failed to parse status JSON: {e}")
                        
                elif status_response.status_code == 404:
                    print(f"❌ Video ID not found: {video_id}")
                    return ""
                    
                else:
                    print(f"⚠️ Status check failed: {status_response.status_code}")
            
            except Exception as e:
                print(f"❌ Error during status check: {str(e)}")
            
            # Dynamic wait time
            wait_time = base_wait_time + (attempt // 5) * 2
            print(f"⏳ Waiting {wait_time} seconds before next attempt...")
            time.sleep(wait_time)
            attempt += 1
        
        print(f"⏰ Video generation timed out after {max_attempts} attempts")
        return ""

    def _generate_openai_tts_audio(self, text, voice_id=None):
        """ENHANCED: Generate audio using OpenAI's TTS API with voice mapping"""
        try:
            # Prepare text for voice
            voice_text = self._prepare_text_for_voice(text)
            
            # Map custom voice IDs to OpenAI voices
            voice_mapping = {
                '2d5b0e6cf36f460aa7fc47e3eee4ba54': 'nova',    # Female professional (Rachel)
                'd7bbcdd6964c47bdaae26decade4a933': 'onyx',    # Male professional (David)
                '4d2b8e6cf36f460aa7fc47e3eee4ba12': 'shimmer', # Female friendly (Emma)
                '3a1c7d5bf24e350bb6dc46e2dee3ab21': 'echo',    # Male casual (Michael)
                '1bd001e7e50f421d891986aad5158bc8': 'alloy',   # Female warm (Olivia)
            }
            
            openai_voice = voice_mapping.get(voice_id, 'nova')  # Default to nova
            
            print(f"🔊 Using OpenAI TTS with voice: {openai_voice} (mapped from {voice_id})")
            
            response = self.client.audio.speech.create(
                model="tts-1-hd",  # Use HD model for better quality
                voice=openai_voice,
                input=voice_text,
                response_format="mp3",
                speed=0.9  # Slightly slower for clarity
            )
            
            # Convert to base64 for return
            audio_content = response.content
            audio_base64 = base64.b64encode(audio_content).decode('utf-8')
            
            print(f"✅ OpenAI TTS audio generated: {len(audio_base64)} characters (base64)")
            return f"data:audio/mpeg;base64,{audio_base64}"
            
        except Exception as e:
            print(f"❌ OpenAI TTS error: {str(e)}")
            return None
    
    def _generate_elevenlabs_audio(self, text, voice_id=None):
        """Generate audio using ElevenLabs API with enhanced voice mapping"""
        if not self.eleven_labs_api_key:
            print("ElevenLabs API key not configured")
            return None
        
        # Map our voice IDs to ElevenLabs voice IDs
        elevenlabs_voice_mapping = {
            '2d5b0e6cf36f460aa7fc47e3eee4ba54': '21m00Tcm4TlvDq8ikWAM',  # Rachel
            'd7bbcdd6964c47bdaae26decade4a933': 'VR6AewLTigWG4xSOukaG',  # David
            '4d2b8e6cf36f460aa7fc47e3eee4ba12': 'ErXwobaYiN019PkySvjV',  # Emma
            '3a1c7d5bf24e350bb6dc46e2dee3ab21': 'VR6AewLTigWG4xSOukaG',  # Michael
            '1bd001e7e50f421d891986aad5158bc8': 'oWAxZDx7w5VEj9dCyTzz',  # Olivia
        }
        
        # Use mapped voice or default
        elevenlabs_voice_id = elevenlabs_voice_mapping.get(voice_id, '21m00Tcm4TlvDq8ikWAM')
        
        headers = {
            "xi-api-key": self.eleven_labs_api_key,
            "Content-Type": "application/json"
        }
        
        # Prepare text for voice
        voice_text = self._prepare_text_for_voice(text)
        
        payload = {
            "text": voice_text,
            "model_id": "eleven_monolingual_v1",
            "voice_settings": {
                "stability": 0.5,
                "similarity_boost": 0.75,
                "style": 0.2,
                "use_speaker_boost": True
            }
        }
        
        try:
            response = requests.post(
                f"https://api.elevenlabs.io/v1/text-to-speech/{elevenlabs_voice_id}",
                headers=headers,
                json=payload,
                timeout=15
            )
            
            if response.status_code == 200:
                # Convert to base64
                audio_content = response.content
                audio_base64 = base64.b64encode(audio_content).decode('utf-8')
                
                print(f"✅ ElevenLabs audio generated")
                return f"data:audio/mpeg;base64,{audio_base64}"
            
            print(f"ElevenLabs API error: {response.status_code} - {response.text}")
            return None
        
        except Exception as e:
            print(f"ElevenLabs audio generation error: {str(e)}")
            return None

    def _generate_fallback_audio(self, text, voice_id=None):
        """Generate fallback audio using Web Speech API or simple TTS"""
        try:
            # This would be a fallback - in production you might use other TTS services
            print("⚠️ Using fallback audio generation")
            return None
        except Exception as e:
            print(f"Fallback audio generation error: {str(e)}")
            return None

    def get_fallback_response(self, message, influencer_name=None):
        """Enhanced fallback response when the main system fails"""
        name = influencer_name or "I"
        
        # More contextual fallback responses
        if self._is_product_query(message):
            fallback_responses = [
                f"I'd love to help you find the perfect product! {name} has great taste. Could you be more specific about what you're looking for?",
                f"Product recommendations are one of my specialties! Let me know what category you're interested in and I'll find something amazing.",
                f"Great question about products! {name} always finds the best deals. What's your budget and preferences?",
            ]
        else:
            fallback_responses = [
                f"Thanks for your message! {name} would love to help you with that. Could you tell me a bit more about what you're looking for?",
                f"That's a great question! Let me think about the best way to help you with that.",
                f"I appreciate you reaching out! {name} always enjoys connecting with followers. What specific information can I help you find?",
                f"Thanks for asking! I want to give you the most helpful response possible. Could you provide a bit more detail about what you need?"
            ]
        
        import random
        return random.choice(fallback_responses)

    def get_comprehensive_chat_response(self, message, influencer_id=None, session_id=None, 
                                      influencer_name=None, voice_mode=False, video_mode=True):
        """ENHANCED: Comprehensive chat response with all features including knowledge integration"""
        try:
            # Generate text response with knowledge
            text_response = self.get_chat_response_with_knowledge(
                message=message,
                influencer_id=influencer_id,
                session_id=session_id,
                influencer_name=influencer_name,
                db=self.db,
                voice_mode=voice_mode
            )
            
            response_data = {
                'text': text_response,
                'session_id': session_id or f"session_{int(time.time())}",
                'video_url': '',
                'audio_url': '',
                'has_avatar': False,
                'voice_id': Config.DEFAULT_VOICE_ID,
                'knowledge_enhanced': True,
                'products_included': self._is_product_query(message),
                'influencer': {
                    'username': influencer_name or 'AI Assistant',
                    'bio': '',
                    'has_knowledge_documents': False
                }
            }
            
            if influencer_id and self.db:
                influencer = self.db.get_influencer(influencer_id)
                if influencer:
                    response_data['has_avatar'] = bool(influencer.get('heygen_avatar_id'))
                    response_data['voice_id'] = influencer.get('preferred_voice_id') or influencer.get('voice_id') or Config.DEFAULT_VOICE_ID
                    response_data['influencer'] = {
                        'username': influencer['username'],
                        'bio': influencer.get('bio', ''),
                        'has_knowledge_documents': bool(influencer.get('bio') or influencer.get('expertise') or influencer.get('personality'))
                    }
                    
                    # Generate audio response if voice mode is enabled
                    if voice_mode and not video_mode:
                        audio_url = self.generate_audio_response(
                            text_response, 
                            response_data['voice_id']
                        )
                        if audio_url:
                            response_data['audio_url'] = audio_url
                    
                    # Generate video response if avatar is available and video mode is enabled
                    if video_mode and response_data['has_avatar']:
                        video_url = self.generate_enhanced_video_response(
                            text_response,
                            influencer_id,
                            response_data['voice_id']
                        )
                        if video_url:
                            response_data['video_url'] = video_url
            
            return response_data
            
        except Exception as e:
            print(f"❌ Comprehensive chat response error: {str(e)}")
            return {
                'text': self.get_fallback_response(message, influencer_name),
                'session_id': session_id or f"session_{int(time.time())}",
                'video_url': '',
                'audio_url': '',
                'has_avatar': False,
                'voice_id': Config.DEFAULT_VOICE_ID,
                'knowledge_enhanced': False,
                'products_included': False,
                'error': str(e)
            }

# Backwards compatibility - keep the original Chatbot class
class Chatbot(EnhancedChatbot):
    """Backwards compatible Chatbot class"""
    
    def generate_voice_audio(self, text, voice_id=None):
        """Backwards compatibility method"""
        return self.generate_audio_response(text, voice_id)