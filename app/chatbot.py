import openai
from sentence_transformers import SentenceTransformer
import numpy as np
from datetime import datetime
import json
import requests
import time
from config import Config

class Chatbot:
    def __init__(self):
        self.client = openai.OpenAI(api_key=Config.OPENAI_API_KEY)
        self.embedding_model = None  # Will be loaded when needed
        self.heygen_api_key = Config.HEYGEN_API_KEY
        
    def get_embedding_model(self):
        """Lazy load the embedding model to save memory"""
        if self.embedding_model is None:
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        return self.embedding_model
    
    def get_chat_response_with_knowledge(self, message, influencer_id=None, session_id=None, 
                                       influencer_name=None, db=None):
        """Generate a conversational response using RAG with user's knowledge base"""
        try:
            # Get relevant knowledge from user's knowledge base
            knowledge_context = ""
            personal_context = ""
            
            if db and influencer_id:
                # Generate embedding for the query
                model = self.get_embedding_model()
                query_embedding = model.encode([message])[0].tolist()
                
                # Search knowledge base
                knowledge_results = db.search_knowledge_base(influencer_id, query_embedding, limit=3)
                
                # Get personal information
                personal_info = db.get_personal_knowledge(influencer_id)
                
                # Build knowledge context
                if knowledge_results:
                    relevant_chunks = []
                    for result in knowledge_results:
                        if result['similarity'] > 0.3:  # Only include relevant results
                            relevant_chunks.append(f"From {result['document_name']}: {result['text']}")
                    
                    if relevant_chunks:
                        knowledge_context = f"\n\nRelevant information from your knowledge base:\n" + "\n".join(relevant_chunks)
                
                # Build personal context
                if personal_info:
                    personal_parts = []
                    if personal_info.get('bio'):
                        personal_parts.append(f"About you: {personal_info['bio']}")
                    if personal_info.get('industry'):
                        personal_parts.append(f"Industry: {personal_info['industry']}")
                    if personal_info.get('expertise'):
                        personal_parts.append(f"Expertise: {personal_info['expertise']}")
                    if personal_info.get('values'):
                        personal_parts.append(f"Values: {personal_info['values']}")
                    if personal_info.get('communication_style'):
                        personal_parts.append(f"Communication style: {personal_info['communication_style']}")
                    
                    if personal_parts:
                        personal_context = f"\n\nPersonal information about you:\n" + "\n".join(personal_parts)
            
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

    # [Rest of the class methods remain the same...]
    # (Including product recommendations, voice generation, etc.)
    
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
            chat_history = self.db.get_chat_history(influencer_id, session_id, limit=5)
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
        
        # Use the LLM to generate response
        response = self.llm.invoke(prompt)
        return response.content if hasattr(response, 'content') else str(response)

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
            chat_history = self.db.get_chat_history(influencer_id, session_id, limit=5)
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
        
        # Use the LLM to generate response
        response = self.llm.invoke(prompt)
        return response.content if hasattr(response, 'content') else str(response)

    def get_response(self, message, influencer_id, session_id=None, influencer_name=None, voice_mode=False, voice_id=None):
        """Generate a response with optional product recommendations and voice."""
        # Check if the message indicates product interest
        is_product_query, product_query = self.analyze_message_for_product_intent(message)
        
        # Determine if we should promote a product based on conversation settings
        should_promote = False
        if session_id and self.db:
            should_promote = self.should_promote_product(influencer_id, session_id)

        if voice_id:
            # Pass the user's selected voice to video generation
            video_url = self.generate_avatar_video_with_voice(chat_response, influencer_id, voice_id)
        else:
            video_url = self.generate_avatar_video(chat_response, influencer_id)        
            
        # Generate conversational response
        chat_response = self.get_chat_response(message, influencer_id, session_id, influencer_name)
        
        # Handle product recommendations
        full_response = chat_response
        
        # If explicit product interest is detected, use that query
        if is_product_query:
            product_recommendations = self.get_product_recommendations(product_query, influencer_id)
            full_response = f"{chat_response}\n\n{product_recommendations}"
            was_promotion = True
        # Otherwise, if it's time to promote based on settings, use the default product
        elif should_promote:
            product_query = self.get_product_query_for_promotion(influencer_id)
            if product_query:
                product_recommendations = self.get_product_recommendations(product_query, influencer_id)
                full_response = f"{chat_response}\n\n{product_recommendations}"
                was_promotion = True
            else:
                was_promotion = False
        else:
            was_promotion = False
        
        # Update conversation counter if we have a session and db
        if session_id and self.db:
            self.db.increment_conversation_counter(influencer_id, session_id, was_promotion)
        
        # Generate video avatar for the chat response only (not including product recommendations)
        video_url = self.generate_avatar_video(chat_response, influencer_id)
        
        # Generate audio if voice mode is enabled
        audio_url = None
        if voice_mode:
            try:
                # Use the influencer's voice if available, otherwise default
                if voice_id:
                    audio_url = self.generate_voice_audio(chat_response, voice_id)
                else:
                    audio_url = self.generate_voice_audio(chat_response)
            except Exception as e:
                print(f"Voice generation error: {str(e)}")
                audio_url = None
            
        return {
            "text": full_response,
            "chat_response": chat_response,  # Just the conversational part
            "video_url": video_url,
            "audio_url": audio_url,
            "has_product_recommendations": is_product_query or was_promotion,
            "voice_mode": voice_mode
        }


    def get_product_recommendations(self, query: str, influencer_id: str) -> str:
        """Fetch product recommendations with fallback mechanism for available platforms."""
        # Sanitize and clean the query
        query = self.sanitize_query(query)
        
        try:
            # Get influencer's preferred platform (primary affiliate link)
            preferred_platform = self.get_influencer_preferred_platform(influencer_id)
            
            # Try preferred platform first if it's enabled
            if preferred_platform and is_platform_enabled(preferred_platform):
                products = self.fetch_platform_products(query, preferred_platform)
                if products:
                    return self.format_products(products, influencer_id, preferred_platform)
            
            # Try other enabled platforms in order
            enabled_platforms = get_enabled_platforms()
            for platform in enabled_platforms:
                if platform != preferred_platform:  # Skip if already tried
                    try:
                        products = self.fetch_platform_products(query, platform)
                        if products:
                            return self.format_products(products, influencer_id, platform)
                    except Exception as e:
                        print(f"Error with {platform}: {str(e)}")
                        continue
            
            # If no platforms worked, generate AI-based recommendations
            return self.generate_ai_product_recommendations(query, influencer_id)
        
        except Exception as e:
            print(f"Product recommendation error: {str(e)}")
            return self.generate_fallback_recommendations(query)

    def sanitize_query(self, query: str) -> str:
        """Clean and prepare the query for product search."""
        # Remove unnecessary words, limit length
        stop_words = ['recommend', 'suggestions', 'products', 'buy', 'get', 'looking for']
        for word in stop_words:
            query = query.lower().replace(word, '').strip()
        
        # Truncate to reasonable length
        return query[:50]

    def get_influencer_preferred_platform(self, influencer_id: str) -> str:
        """Get the influencer's preferred affiliate platform"""
        if not self.db:
            return None
            
        primary_affiliate = self.db.get_primary_affiliate_link(influencer_id)
        return primary_affiliate.get('platform') if primary_affiliate else None

    def fetch_platform_products(self, query: str, platform: str) -> List[Dict]:
        """Fetch products from a specific platform"""
        if platform == 'rakuten':
            return self.fetch_rakuten_products(query)
        elif platform == 'amazon':
            return self.fetch_amazon_products(query)
        elif platform == 'shareasale':
            return self.fetch_shareasale_products(query)
        elif platform == 'cj_affiliate':
            return self.fetch_cj_products(query)
        else:
            return []

    def fetch_rakuten_products(self, query: str) -> List[Dict]:
        """Fetch products from Rakuten API"""
        if not is_platform_enabled('rakuten'):
            return []
            
        config = AFFILIATE_PLATFORMS['rakuten']
        headers = {
            "Authorization": f"Bearer {config['credentials']['token']}",
            "Content-Type": "application/json"
        }
        
        params = {
            "keyword": query,
            "merchant_id": config['credentials']['merchant_id'],
            "hits": 5,
            "sort": "standard"
        }
        
        try:
            response = requests.get(
                config['base_url'], 
                headers=headers, 
                params=params, 
                timeout=10
            )
            
            if response.status_code == 200:
                products_data = response.json()
                products = products_data.get('items', [])
                return self.transform_products(products, 'rakuten')
        except Exception as e:
            print(f"Rakuten API error: {str(e)}")
        
        return []

    def fetch_amazon_products(self, query: str) -> List[Dict]:
        """Fetch products from Amazon Associates API (PAAPI 5.0)"""
        if not is_platform_enabled('amazon'):
            return []
        
        # Note: Amazon PAAPI 5.0 requires complex authentication
        # For now, return empty list - implement when you get Amazon credentials
        print("Amazon API not yet implemented - credentials needed")
        return []

    def fetch_shareasale_products(self, query: str) -> List[Dict]:
        """Fetch products from ShareASale API"""
        if not is_platform_enabled('shareasale'):
            return []
        
        # ShareASale API implementation
        print("ShareASale API not yet implemented - credentials needed")
        return []

    def fetch_cj_products(self, query: str) -> List[Dict]:
        """Fetch products from CJ Affiliate API"""
        if not is_platform_enabled('cj_affiliate'):
            return []
        
        # CJ Affiliate API implementation
        print("CJ Affiliate API not yet implemented - credentials needed")
        return []

    def generate_ai_product_recommendations(self, query: str, influencer_id: str) -> str:
        """Generate AI-based product recommendations when APIs aren't available"""
        prompt = f"""You are helping an influencer recommend products related to: {query}

        Generate 3-5 realistic, specific product recommendations that would be relevant.
        For each product, provide:
        - A specific product name
        - A realistic price range
        - A brief compelling description
        - Why it's relevant to the query

        Format as a clean, engaging product list that feels natural in a conversation.
        """
        
        try:
            response = self.llm.invoke(prompt)
            ai_response = response.content if hasattr(response, 'content') else str(response)
            
            # Get influencer's affiliate links for formatting
            affiliate_links = self.db.get_affiliate_links(influencer_id) if self.db else []
            
            # Add affiliate context if available
            if affiliate_links:
                primary_link = next((link for link in affiliate_links if link.get('is_primary')), affiliate_links[0])
                platform_name = primary_link.get('platform', '').replace('_', ' ').title()
                
                ai_response += f"\n\n💡 *I can help you find these products on {platform_name} - just let me know what interests you!*"
            else:
                ai_response += f"\n\n💡 *These are some great options to consider for {query}!*"
            
            return ai_response
            
        except Exception as e:
            print(f"AI recommendation error: {str(e)}")
            return self.generate_fallback_recommendations(query)

    def generate_fallback_recommendations(self, query: str) -> str:
        """Generate a fallback recommendation message."""
        fallback_message = f"""I couldn't find specific products for "{query}", 
        but here are some general recommendations:\n\n"""
        
        generic_products = [
            {"productname": "Versatile Tech Accessory", "price": "$49.99", "producturl": "#", "imageurl": ""},
            {"productname": "Stylish Everyday Item", "price": "$29.99", "producturl": "#", "imageurl": ""},
            {"productname": "Practical Lifestyle Product", "price": "$39.99", "producturl": "#", "imageurl": ""},
            {"productname": "Trending Gadget", "price": "$79.99", "producturl": "#", "imageurl": ""},
            {"productname": "Useful Companion Product", "price": "$59.99", "producturl": "#", "imageurl": ""}
        ]
        
        return self.format_products(generic_products, "generic", "generic")

    def transform_products(self, products: List[Dict], platform: str) -> List[Dict]:
        """Transform various product formats to a standard format."""
        standard_products = []
        
        for product in products[:5]:
            standard_product = {
                'productname': product.get('name', product.get('title', 'Unnamed Product')),
                'price': product.get('price', product.get('regularPrice', 'N/A')),
                'producturl': product.get('url', product.get('productUrl', '#')),
                'imageurl': product.get('image', product.get('imageUrl', ''))
            }
            standard_products.append(standard_product)
        
        return standard_products

    def format_products(self, products: List[Dict], influencer_id: str, platform: str) -> str:
        """Format product recommendations with affiliate links"""
        if not products:
            return "Sorry, I couldn't find any products for that search."
        
        # Get influencer's affiliate ID for this platform
        affiliate_id = self.get_affiliate_id_for_platform(influencer_id, platform)
        
        formatted_products = []
        
        for product in products[:5]:  # Limit to 5 items
            title = product.get('productname', 'No title')
            price = product.get('price', 'Price not available')
            url = product.get('producturl', '#')
            image_url = product.get('imageurl', '')
            
            # Create affiliate URL based on platform
            affiliate_url = self.create_affiliate_url(url, platform, affiliate_id)
            
            product_info = f"🛒 **{title}** - {price}\n"
            if image_url:
                product_info += f"📷 [Product Image]({image_url})\n"
            product_info += f"🔗 [View Product]({affiliate_url})"
            
            formatted_products.append(product_info)

        if formatted_products:
            platform_name = AFFILIATE_PLATFORMS.get(platform, {}).get('name', platform.title())
            recommendations = "\n\n".join(formatted_products)
            return f"### Recommended Products from {platform_name}\n\n{recommendations}"
        else:
            return self.generate_ai_product_recommendations(query, influencer_id)

    def get_affiliate_id_for_platform(self, influencer_id: str, platform: str) -> str:
        """Get affiliate ID for a specific platform"""
        if not self.db:
            return ""
            
        affiliate_links = self.db.get_affiliate_links(influencer_id, platform)
        return affiliate_links[0].get('affiliate_id', '') if affiliate_links else ""

    def create_affiliate_url(self, base_url: str, platform: str, affiliate_id: str) -> str:
        """Create platform-specific affiliate URLs"""
        if not affiliate_id:
            return base_url
            
        if platform == 'rakuten':
            return f"{base_url}?mid={affiliate_id}"
        elif platform == 'amazon':
            return f"{base_url}?tag={affiliate_id}"
        elif platform == 'shareasale':
            return f"{base_url}?afftrack={affiliate_id}"
        elif platform == 'cj_affiliate':
            return f"{base_url}?cid={affiliate_id}"
        else:
            return f"{base_url}?ref={affiliate_id}"

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

    def should_promote_product(self, influencer_id, session_id):
        """Determine if it's time to promote a product based on conversation counter and settings"""
        if not self.db or not session_id:
            return False
            
        # Get promotion settings
        settings = self.db.get_promotion_settings(influencer_id)
        if not settings:
            return False
            
        # If always promote at end is enabled, return True
        if settings.get("promote_at_end", False):
            return True
            
        # Get conversation counter
        counter = self.db.get_conversation_counter(influencer_id, session_id)
        if not counter:
            return False
            
        # Check if we've reached the promotion frequency
        message_count = counter.get("message_count", 0)
        promotion_frequency = settings.get("promotion_frequency", 3)
        
        # Check if we've reached the frequency threshold (after incrementing counter)
        return (message_count + 1) % promotion_frequency == 0

    def get_product_query_for_promotion(self, influencer_id):
        """Get the query to use for product promotion"""
        if not self.db:
            return None
            
        # Check for default product in settings
        settings = self.db.get_promotion_settings(influencer_id)
        if settings and settings.get("default_product"):
            return settings.get("default_product")
            
        # Check for default product in products table
        default_product = self.db.get_default_product(influencer_id)
        if default_product:
            return default_product.get("product_query")
            
        # No default product, return None
        return None

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
            
        temp_file = None
        temp_filename = None
        
        try:
            # Use temporary file if audio_file is bytes
            if isinstance(audio_file, bytes):
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.mp3')
                temp_filename = temp_file.name
                temp_file.write(audio_file)
                temp_file.close()  # Close the file explicitly before using it
                audio_path = temp_filename
            else:
                audio_path = audio_file
                
            # Create a file object for the request
            with open(audio_path, 'rb') as file_obj:
                files = {'file': file_obj}
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
            if temp_filename:
                try:
                    # Add a small delay to ensure file is released
                    import time
                    time.sleep(0.1)
                    
                    # Then try to remove it
                    import os
                    if os.path.exists(temp_filename):
                        os.remove(temp_filename)
                except Exception as e:
                    print(f"Warning: Could not remove temporary file {temp_filename}: {str(e)}")
                    # Continue execution even if cleanup fails