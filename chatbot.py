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
import logging
from config import Config

logger = logging.getLogger(__name__)

# Import the affiliate service
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

def is_product_query_simple(message):
    """Simple product query detection for immediate fix"""
    product_keywords = [
        'recommend', 'suggestion', 'what should i buy', 'best product', 
        'looking for', 'need help choosing', 'product', 'buy', 'purchase',
        'shopping', 'recommendation', 'suggest', 'find', 'help me find',
        'computer', 'laptop', 'phone', 'headphones', 'camera'
    ]
    
    message_lower = message.lower()
    return any(keyword in message_lower for keyword in product_keywords)

class EnhancedChatbot:
    """Enhanced chatbot with knowledge base, affiliate integration, and voice capabilities"""
    
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

    def get_comprehensive_chat_response(self, message, influencer_id=None, session_id=None, 
                                    influencer_name=None, voice_mode=False, video_mode=True):
        """FIXED: Comprehensive chat response with all features and correct return format"""
        try:
            logger.info(f"🤖 Processing comprehensive chat for {influencer_name}: {message[:50]}...")
            
            # Get influencer data
            influencer = self.db.get_influencer(influencer_id) if self.db and influencer_id else None
            
            # Generate text response with complete knowledge integration
            text_response = self.get_chat_response_with_complete_knowledge(
                message=message,
                influencer_id=influencer_id,
                session_id=session_id,
                influencer_name=influencer_name,
                db=self.db,
                voice_mode=voice_mode
            )
            
            # Determine if products were included
            products_included = self._is_product_query(message) and self.affiliate_service and influencer_id
            
            # Prepare comprehensive response data
            response_data = {
                'text': text_response,
                'session_id': session_id or f"session_{int(time.time())}",
                'video_url': '',
                'audio_url': '',
                'has_avatar': False,
                'has_audio': False,
                'has_video': False,
                'voice_id': Config.DEFAULT_VOICE_ID,
                'knowledge_enhanced': True,
                'products_included': products_included,
                'influencer': {
                    'username': influencer_name or 'AI Assistant',
                    'bio': '',
                    'has_knowledge_documents': False,
                    'avatar_type': 'none'
                }
            }
            
            if influencer:
                response_data['has_avatar'] = bool(influencer.get('heygen_avatar_id'))
                response_data['voice_id'] = influencer.get('preferred_voice_id') or influencer.get('voice_id') or Config.DEFAULT_VOICE_ID
                response_data['influencer'] = {
                    'username': influencer['username'],
                    'bio': influencer.get('bio', ''),
                    'has_knowledge_documents': bool(influencer.get('bio') or influencer.get('expertise') or influencer.get('personality')),
                    'avatar_type': influencer.get('avatar_type', 'none'),
                    'avatar_id': influencer.get('heygen_avatar_id'),
                    'expertise': influencer.get('expertise', ''),
                    'personality': influencer.get('personality', '')
                }
            
            logger.info(f"✅ Comprehensive response generated with products: {products_included}")
            return response_data
            
        except Exception as e:
            logger.error(f"❌ Comprehensive chat response error: {str(e)}")
            return {
                'text': self.get_fallback_response(message, influencer_name),
                'session_id': session_id or f"session_{int(time.time())}",
                'video_url': '',
                'audio_url': '',
                'has_avatar': False,
                'has_audio': False,
                'has_video': False,
                'voice_id': Config.DEFAULT_VOICE_ID,
                'knowledge_enhanced': False,
                'products_included': False,
                'error': str(e)
            }

    def get_chat_response_with_complete_knowledge(self, message, influencer_id=None, session_id=None, 
                                                influencer_name=None, db=None, voice_mode=False):
        """Enhanced chat response with proper affiliate product integration"""
        try:
            knowledge_context = ""
            personal_context = ""
            product_recommendations = ""
            products_included = False
            
            # STEP 1: Check if this is a product query
            if self._is_product_query(message):
                logger.info(f"🛒 PRODUCT QUERY DETECTED: {message[:50]}...")
                
                if self.affiliate_service and influencer_id:
                    try:
                        recommendations = self.affiliate_service.get_product_recommendations(
                            query=message,
                            influencer_id=influencer_id,
                            limit=3
                        )
                        
                        if recommendations and recommendations.get('products'):
                            logger.info(f"✅ Found {len(recommendations['products'])} affiliate products")
                            product_recommendations = ProductRecommendationFormatter.format_recommendations(
                                recommendations['products'],
                                {'platform_name': 'Rakuten Advertising'}
                            )
                            products_included = True
                        else:
                            logger.info("📝 No affiliate products found, generating AI recommendations")
                            product_recommendations = self.get_ai_product_recommendations(message, influencer_id)
                            products_included = True
                            
                    except Exception as e:
                        logger.error(f"Affiliate product search error: {e}")
                        product_recommendations = self.get_ai_product_recommendations(message, influencer_id)
                        products_included = True
                else:
                    logger.info("⚠️ No affiliate service, generating AI recommendations")
                    product_recommendations = self.get_ai_product_recommendations(message, influencer_id or 'unknown')
                    products_included = True
            
            # STEP 2: Get personal context
            if db and influencer_id:
                influencer = db.get_influencer(influencer_id)
                if influencer:
                    personal_parts = []
                    if influencer.get('bio'):
                        personal_parts.append(f"About me: {influencer['bio']}")
                    if influencer.get('expertise'):
                        personal_parts.append(f"Expertise: {influencer['expertise']}")
                    if influencer.get('personality'):
                        personal_parts.append(f"Personality: {influencer['personality']}")
                    personal_context = "\n".join(personal_parts)
            
            # STEP 3: Get knowledge context (if RAG available)
            if self.rag_processor and influencer_id:
                try:
                    if hasattr(self.rag_processor, 'search_knowledge'):
                        knowledge_results = self.rag_processor.search_knowledge(message, influencer_id)
                        if knowledge_results:
                            knowledge_context = "\n".join([chunk['content'] for chunk in knowledge_results])
                    else:
                        logger.warning("⚠️ RAGProcessor lacks search_knowledge method, skipping knowledge search")
                except Exception as e:
                    logger.error(f"RAG search error: {e}")
            
            # STEP 4: Generate base response
            prompt = f"""You are {influencer_name or 'AI Assistant'}, a helpful influencer.
            User asked: {message}
            Personal context: {personal_context}
            Knowledge context: {knowledge_context}
            Respond naturally and helpfully. If products were requested, include this at the end:
            {product_recommendations}
            """
            
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a helpful influencer assistant."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.7
            )
            
            text_response = response.choices[0].message.content.strip()
            
            # Ensure product recommendations are included
            if products_included and product_recommendations and product_recommendations not in text_response:
                text_response += "\n\n" + product_recommendations
            
            logger.info(f"✅ Generated response: {text_response[:100]}...")
            return text_response
            
        except Exception as e:
            logger.error(f"❌ Chat response error: {e}")
            return self.get_fallback_response(message, influencer_name)

    def _is_simple_product_query(self, message):
        """Detect simple product queries that don't need knowledge context"""
        simple_product_phrases = [
            'product recommendation', 'what product', 'recommend a product',
            'suggest product', 'best product', 'product for', 'buy product',
            'recommend products', 'product suggestions'
        ]
        
        message_lower = message.lower().strip()
        return any(phrase in message_lower for phrase in simple_product_phrases)   

    def _format_product_recommendations(self, products: List[Dict]) -> str:
        """FIXED: Format product recommendations for chat display"""
        if not products:
            return ""
        
        formatted = "\n\n🛍️ **Here are some great products I found:**\n\n"
        
        for i, product in enumerate(products[:3], 1):
            price_str = f"${product['price']:.2f}" if product.get('price', 0) > 0 else "See price"
            rating_str = f"⭐ {product['rating']:.1f}" if product.get('rating', 0) > 0 else ""
            
            formatted += f"**{i}. {product.get('name', 'Product')}**\n"
            formatted += f"💰 {price_str}"
            
            if rating_str:
                formatted += f" | {rating_str}"
            
            if product.get('shop_name'):
                formatted += f" | 🏪 {product['shop_name']}"
            
            if product.get('description'):
                description = product['description'][:150] + "..." if len(product['description']) > 150 else product['description']
                formatted += f"\n📝 {description}\n"
            
            if product.get('affiliate_url'):
                formatted += f"🔗 [View Product]({product['affiliate_url']})\n\n"
            else:
                formatted += "\n"
        
        formatted += f"💡 *Found these through my affiliate partnerships. I may earn a small commission if you make a purchase.*\n"
        
        return formatted
    
    def _build_enhanced_system_prompt(self, influencer_name, personal_context, knowledge_context, voice_mode=False, has_products=False):
        """Build enhanced system prompt with product awareness"""
        base_name = influencer_name or "the influencer"
        
        product_instructions = ""
        if has_products:
            product_instructions = """
    PRODUCT RECOMMENDATION MODE:
    - You are providing specific product recommendations
    - Introduce the products naturally and enthusiastically  
    - Explain why these specific products are great choices
    - Be genuine and helpful in your recommendations
    - Show expertise and personal touch in your suggestions
    - Mention that you've found some specific options for them
    """
        
        voice_instructions = ""
        if voice_mode:
            voice_instructions = """
    VOICE RESPONSE GUIDELINES:
    - Keep responses conversational and natural for voice output
    - Use shorter sentences and clearer pronunciation  
    - Be more expressive and engaging since this will be spoken
    - Limit response to 3-4 sentences for optimal voice delivery
    """
        
        system_prompt = f"""You are an AI assistant representing {base_name}. You help users by providing helpful, engaging, and personalized responses.

    CORE INSTRUCTIONS:
    - Be conversational, friendly, and authentic
    - Provide helpful and accurate information based on your knowledge
    - When users ask for product recommendations, provide specific, helpful suggestions
    - Stay true to the personality and expertise described below
    - Use your knowledge base information when it's relevant to the user's question
    - Be solution-oriented and genuinely helpful

    {product_instructions}

    {voice_instructions}

    {personal_context}

    {knowledge_context}

    RESPONSE STYLE:
    - Use a natural, conversational tone that matches your personality
    - Be helpful and solution-oriented
    - Reference your knowledge and expertise when relevant
    - Keep responses engaging and personable
    - Show genuine enthusiasm when helping with recommendations
    - Be specific and actionable in your advice

    Remember: You are representing {base_name}, so respond as them, using their knowledge, personality, and expertise to provide the most helpful and authentic response possible."""

        return system_prompt
    
    def _is_product_query(self, message):
        """FIXED: Enhanced product query detection with more keywords"""
        product_keywords = [
            # Direct product requests
            'recommend', 'recommendation', 'suggest', 'suggestion', 'product', 'products',
            
            # Shopping intent
            'buy', 'purchase', 'shopping', 'shop', 'get', 'need', 'want', 'looking for',
            
            # Comparison and choice
            'best', 'top', 'good', 'better', 'compare', 'vs', 'versus', 'choice', 'option',
            
            # Specific phrases
            'what should i buy', 'help me find', 'which one', 'what do you think',
            'worth buying', 'should i get', 'alternatives', 'similar to',
            
            # Price and value
            'cheap', 'affordable', 'expensive', 'price', 'cost', 'budget', 'deal', 'sale',
            
            # Reviews and opinions
            'review', 'opinion', 'thoughts on', 'experience with', 'worth it',
            
            # Categories (add more as needed)
            'laptop', 'phone', 'camera', 'headphones', 'shoes', 'clothes', 'book', 'game'
        ]
        
        message_lower = message.lower()
        
        # Check if any product keyword is in the message
        has_product_keyword = any(keyword in message_lower for keyword in product_keywords)
        
        # Additional checks for product intent
        question_indicators = ['what', 'which', 'how', 'where', 'should i']
        has_question = any(indicator in message_lower for indicator in question_indicators)
        
        # Strong product indicators
        strong_indicators = [
            'product recommendation', 'recommend a', 'suggest a', 'best for',
            'help me choose', 'what to buy', 'should i buy', 'looking to buy'
        ]
        has_strong_indicator = any(indicator in message_lower for indicator in strong_indicators)
        
        # If it has strong indicators, definitely a product query
        if has_strong_indicator:
            return True
        
        # If it has product keywords and question words, likely a product query
        if has_product_keyword and has_question:
            return True
        
        # Check for specific product request patterns
        product_patterns = [
            'recommend', 'suggest', 'best', 'good', 'help me find', 'looking for',
            'what should i', 'which', 'need a', 'want a'
        ]
        
        return any(pattern in message_lower for pattern in product_patterns)

    def get_ai_product_recommendations(self, query: str, influencer_id: str) -> str:
        """FIXED: Generate AI-based product recommendations with affiliate integration"""
        try:
            # Get influencer's affiliate links for context
            affiliate_platforms = []
            if self.db:
                try:
                    affiliate_links = self.db.get_affiliate_links(influencer_id)
                    affiliate_platforms = [link.get('platform', '') for link in affiliate_links if link.get('is_active', True)]
                except Exception as e:
                    print(f"Error getting affiliate links: {e}")
            
            platform_context = ""
            if affiliate_platforms:
                platform_context = f" I have connections with {', '.join(affiliate_platforms)} to help you find the best deals."
            
            prompt = f"""You are helping an influencer recommend products related to: {query}

    Generate 3 realistic, specific product recommendations that would be relevant.
    For each product, provide:
    - A specific product name
    - A realistic price range  
    - A brief compelling description (1-2 sentences)
    - Why it's relevant to the query

    Format as a natural, engaging response that feels like personal recommendations.{platform_context}

    Start with a friendly introduction like "Here are some great options I'd recommend:" """
            
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a helpful product recommendation assistant who gives personalized, natural recommendations."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=400,
                temperature=0.7
            )
            
            ai_response = response.choices[0].message.content.strip()
            
            # Add affiliate context if available
            if affiliate_platforms:
                ai_response += f"\n\n💡 *I can help you find these products through my partner networks. Let me know what interests you most!*"
            else:
                ai_response += f"\n\n💡 *These are general recommendations. I'm working on connecting affiliate partners to bring you specific deals!*"
            
            print(f"✅ AI product recommendations generated: {len(ai_response)} characters")
            return ai_response
            
        except Exception as e:
            print(f"❌ AI product recommendations error: {e}")
            return f"I'd love to help you find great {query} options! What specific features or budget are you considering?"

    # FIXED: Voice generation methods with correct signatures
    def generate_audio_response(self, text_response, voice_id=None):
        """FIXED: Generate audio response using influencer's selected voice with correct signature"""
        try:
            if not voice_id:
                voice_id = Config.DEFAULT_VOICE_ID
            
            logger.info(f"🔊 Generating audio response with voice: {voice_id}")
            
            # Use OpenAI TTS as primary option
            audio_url = self._generate_openai_tts_audio(text_response, voice_id)
            
            if audio_url:
                return audio_url
            
            # Fallback to ElevenLabs if available
            if self.eleven_labs_api_key:
                return self._generate_elevenlabs_audio(text_response, voice_id)
            
            return None
                
        except Exception as e:
            logger.error(f"❌ Audio response generation error: {e}")
            return None

    def generate_voice_audio(self, text, voice_id=None):
        """FIXED: Backwards compatibility method with correct signature"""
        return self.generate_audio_response(text, voice_id)

    def _generate_openai_tts_audio(self, text, voice_id=None):
        """FIXED: Generate audio using OpenAI's TTS API with voice mapping"""
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
            
            # Handle custom voice IDs (voice clones)
            if voice_id and voice_id.startswith('custom_'):
                # For custom voices, use a similar sounding default voice
                openai_voice = 'nova'  # Default for custom voices
                logger.info(f"🔊 Using default voice for custom voice ID: {voice_id}")
            else:
                openai_voice = voice_mapping.get(voice_id, 'nova')
            
            logger.info(f"🔊 Using OpenAI TTS with voice: {openai_voice} (mapped from {voice_id})")
            
            response = self.client.audio.speech.create(
                model="tts-1-hd",
                voice=openai_voice,
                input=voice_text,
                response_format="mp3",
                speed=0.9
            )
            
            # Convert to base64 for return
            audio_content = response.content
            audio_base64 = base64.b64encode(audio_content).decode('utf-8')
            
            logger.info(f"✅ OpenAI TTS audio generated")
            return f"data:audio/mpeg;base64,{audio_base64}"
            
        except Exception as e:
            logger.error(f"❌ OpenAI TTS error: {str(e)}")
            return None

    def _generate_elevenlabs_audio(self, text, voice_id=None):
        """FIXED: Generate audio using ElevenLabs API with proper error handling"""
        if not self.eleven_labs_api_key:
            print("ElevenLabs API key not configured")
            return None
        
        # If no specific voice ID is provided, use default
        if not voice_id or voice_id.startswith('custom_'):
            voice_id = "21m00Tcm4TlvDq8ikWAM"  # Default ElevenLabs voice
        
        headers = {
            "xi-api-key": self.eleven_labs_api_key,
            "Content-Type": "application/json"
        }
        
        payload = {
            "text": self._prepare_text_for_voice(text),
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
                timeout=15
            )
            
            if response.status_code == 200:
                # Convert to base64
                audio_content = response.content
                audio_base64 = base64.b64encode(audio_content).decode('utf-8')
                
                print(f"✅ ElevenLabs TTS audio generated")
                return f"data:audio/mpeg;base64,{audio_base64}"
            else:
                print(f"ElevenLabs API error: {response.status_code} - {response.text}")
                return None
        
        except Exception as e:
            print(f"ElevenLabs audio generation error: {str(e)}")
            return None

    def _prepare_text_for_voice(self, text):
        """FIXED: Prepare text specifically for voice generation"""
        lines = text.split('\n')
        clean_lines = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('🛍️') and not line.startswith('**Product') and not line.startswith('💰'):
                line = line.replace('**', '').replace('*', '').replace('#', '')
                clean_lines.append(line)
        
        clean_text = '. '.join(clean_lines)
        
        # Limit to reasonable length for voice
        if len(clean_text) > 400:
            sentences = clean_text.split('. ')
            truncated = '. '.join(sentences[:4])
            if not truncated.endswith('.'):
                truncated += '.'
            return truncated
        
        return clean_text

    def generate_enhanced_video_response(self, text_response, influencer_id, voice_id=None):
        """FIXED: Generate video response with enhanced voice integration"""
        if not self.db or not influencer_id:
            logger.error("❌ No database or influencer ID for video generation")
            return ""
        
        try:
            # Get influencer data with avatar and voice info
            influencer = self.db.get_influencer(influencer_id)
            if not influencer:
                logger.error(f"❌ Influencer not found: {influencer_id}")
                return ""
            
            avatar_id = influencer.get('heygen_avatar_id')
            if not avatar_id:
                logger.error(f"❌ No avatar ID found for influencer: {influencer_id}")
                return ""
            
            # Use influencer's selected voice or provided voice_id
            if not voice_id:
                voice_id = influencer.get('preferred_voice_id') or influencer.get('voice_id') or Config.DEFAULT_VOICE_ID
            
            logger.info(f"🎬 Generating video with avatar: {avatar_id}, voice: {voice_id}")
            
            return self.generate_video_response(text_response, avatar_id, voice_id)
            
        except Exception as e:
            logger.error(f"❌ Enhanced video generation error: {e}")
            return ""

    def generate_video_response(self, text_response, avatar_id, voice_id=None):
        """Generate video response using HeyGen with enhanced error handling"""
        if not avatar_id or not text_response:
            print("❌ Missing avatar_id or text_response for video generation")
            return ""
        
        try:
            print(f"🎬 Generating video for avatar: {avatar_id} with voice: {voice_id}")
            
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
            
            response = requests.post(
                "https://api.heygen.com/v2/video/generate",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            print(f"📡 Video generation response status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                
                if not result.get('error') and result.get('data'):
                    video_id = result['data'].get('video_id')
                    if video_id:
                        print(f"✅ Video generation started, ID: {video_id}")
                        return self._poll_video_status(video_id, headers)
                    else:
                        print("❌ No video_id in response")
                        return ""
                else:
                    print(f"❌ Video generation failed: {result.get('error', 'Unknown error')}")
                    return ""
            else:
                print(f"❌ Request failed with status {response.status_code}: {response.text}")
                return ""
                
        except Exception as e:
            print(f"❌ Video generation error: {str(e)}")
            return ""
    
    def _prepare_text_for_video(self, text):
        """FIXED: Prepare text for video generation by cleaning and limiting length"""
        lines = text.split('\n')
        clean_lines = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('🛍️') and not line.startswith('**Product'):
                clean_lines.append(line)
        
        clean_text = ' '.join(clean_lines)
        
        # Limit to reasonable length for video
        if len(clean_text) > 400:
            sentences = clean_text.split('. ')
            truncated = '. '.join(sentences[:3])
            if not truncated.endswith('.'):
                truncated += '.'
            return truncated
        
        return clean_text
    
    def _poll_video_status(self, video_id, headers, max_attempts=25):
        """Poll video status with improved timing"""
        attempt = 0
        base_wait_time = 3
        
        while attempt < max_attempts:
            try:
                status_response = requests.get(
                    f"https://api.heygen.com/v1/video_status.get?video_id={video_id}",
                    headers=headers,
                    timeout=15
                )
                
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    
                    if "data" in status_data:
                        data = status_data["data"]
                        status = data.get("status", "unknown")
                        video_url = data.get("video_url", "")
                        
                        print(f"🎬 Attempt {attempt + 1}: Video status: {status}")
                        
                        if status == "completed" and video_url:
                            print(f"✅ Video completed: {video_url}")
                            return video_url
                        elif status == "failed":
                            print(f"❌ Video generation failed: {data.get('error', 'Unknown error')}")
                            return ""
                        elif status in ["processing", "pending", "waiting", "queued"]:
                            print(f"⏳ Video status: {status}, waiting...")
                        
            except Exception as e:
                print(f"❌ Error during status check: {str(e)}")
            
            wait_time = base_wait_time + (attempt // 5) * 2
            time.sleep(wait_time)
            attempt += 1
        
        print(f"⏰ Video generation timed out after {max_attempts} attempts")
        return ""

    def get_fallback_response(self, message, influencer_name=None):
        """Enhanced fallback response"""
        name = influencer_name or "I"
        
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
            ]
        
        import random
        return random.choice(fallback_responses)
    
    def get_emergency_product_response(self, message, influencer_name):
        """Emergency product response when affiliate service fails"""
        try:
            client = openai.OpenAI(api_key=Config.OPENAI_API_KEY)
            
            prompt = f"""You are {influencer_name}, helping someone with product recommendations for: {message}

    Generate 3 realistic, specific product recommendations. For each:
    - Specific product name
    - Realistic price range  
    - Brief compelling description
    - Why it's relevant

    Format as natural, engaging recommendations. Start with "Here are some great options I'd recommend:"""
            
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": f"You are {influencer_name}, a helpful influencer who gives product recommendations."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=400,
                temperature=0.7
            )
            
            ai_response = response.choices[0].message.content.strip()
            ai_response += "\n\n💡 *These are general recommendations. I'm working on getting you the best deals through my affiliate partnerships!*"
            
            return ai_response
            
        except Exception as e:
            print(f"Emergency product response error: {e}")
            return f"I'd love to help you find great {message.lower()} options! What specific features or budget are you considering?"

# FIXED: Backwards compatibility
class Chatbot(EnhancedChatbot):
    """FIXED: Backwards compatible Chatbot class with all required methods"""
    
    def generate_voice_audio(self, text, voice_id=None):
        """FIXED: Backwards compatibility method with correct signature"""
        return self.generate_audio_response(text, voice_id)
        
    def get_chat_response_with_knowledge(self, message, influencer_id=None, session_id=None, 
                                       influencer_name=None, db=None, voice_mode=False):
        """FIXED: Backwards compatibility method"""
        return self.get_chat_response_with_complete_knowledge(
            message, influencer_id, session_id, influencer_name, db, voice_mode
        )