import requests
from langchain_openai import ChatOpenAI
from config import OPENAI_API_KEY, APIFY_API_KEY, HEYGEN_API_KEY

class Chatbot:
    def __init__(self):
        self.llm = ChatOpenAI(openai_api_key=OPENAI_API_KEY)
        self.heygen_api_key = HEYGEN_API_KEY
        self.apify_api_key = APIFY_API_KEY

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

    def get_chat_response(self, message):
        """Generate a conversational response."""
        prompt = f"""You are a friendly, helpful AI assistant for an influencer. 
        Respond to the following message in a conversational, engaging way:
        
        User message: {message}
        
        Keep your response concise (2-3 sentences max) and personable."""
        
        response = self.llm.invoke(prompt)
        return response.content if hasattr(response, 'content') else str(response)

    def get_response(self, message, influencer_id, influencer_name=None):
        """Generate a response with optional product recommendations."""
        # Check if the message indicates product interest
        is_product_query, product_query = self.analyze_message_for_product_intent(message)
        
        # Generate conversational response
        chat_response = self.get_chat_response(message)
        
        # If product interest is detected, add product recommendations
        if is_product_query:
            product_recommendations = self.get_product_recommendations(product_query, influencer_id)
            full_response = f"{chat_response}\n\n{product_recommendations}"
        else:
            full_response = chat_response
        
        # Generate video avatar for the chat response only (not including product recommendations)
        video_url = self.generate_avatar_video(chat_response, influencer_id)
        
        return {
            "text": full_response,
            "chat_response": chat_response,  # Just the conversational part
            "video_url": video_url,
            "has_product_recommendations": is_product_query
        }
    
    def generate_avatar_video(self, text, avatar_id):
        """Generate avatar video using HeyGen API"""
        headers = {
            "X-Api-Key": self.heygen_api_key,
            "Content-Type": "application/json"
        }
        
        # Ensure text isn't too long for video generation
        if len(text) > 500:
            text = text[:497] + "..."
            
        payload = {
            "avatar_id": avatar_id,
            "text": text,
            "voice_id": "1bd001e7e50f421d891986aad5158bc8"  # Default voice
        }
        
        try:
            response = requests.post(
                "https://api.heygen.com/v1/videos.generate",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                return response.json().get("video_url", "")
            else:
                print(f"Error generating video: {response.text}")
                return ""
        except Exception as e:
            print(f"Exception generating video: {str(e)}")
            return ""