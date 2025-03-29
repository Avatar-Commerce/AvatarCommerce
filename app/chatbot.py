import requests
from langchain_openai import ChatOpenAI
from config import OPENAI_API_KEY, APIFY_API_KEY

class Chatbot:
    def __init__(self):
        self.llm = ChatOpenAI(openai_api_key=OPENAI_API_KEY)

    def get_product_recommendations(self, query, influencer_id):
        """Fetch product recommendations from Amazon using Apify API."""
        apify_url = "https://api.apify.com/v2/acts/apify~amazon-scraper/run-sync-get-dataset"
        params = {
            "token": APIFY_API_KEY,
            "queries": [query],
            "maxResults": 5
        }
        response = requests.post(apify_url, json=params)
        
        if response.status_code == 200:
            products = response.json()
            return self.format_products(products, influencer_id)
        else:
            return "Sorry, I couldn't fetch product recommendations at the moment."

    def format_products(self, products, influencer_id):
        """Format product recommendations and append influencer affiliate link."""
        formatted_products = []
        for product in products.get("items", [])[:5]:  # Limit to 5 items
            title = product.get("title", "No title")
            price = product.get("price", "N/A")
            url = product.get("url", "#")
            
            # Append affiliate tracking
            affiliate_url = f"{url}?tag={influencer_id}"
            
            formatted_products.append(f"🛒 {title} - {price}\n🔗 [Buy Now]({affiliate_url})")

        return "\n\n".join(formatted_products) if formatted_products else "No products found."

    def get_response(self, message, influencer_id):
        """Determine if it's a product request or a normal chat request."""
        if "recommend" in message.lower():
            query = message.replace("recommend", "").strip()
            return self.get_product_recommendations(query, influencer_id)
        
        prompt = f"Influencer Chatbot: {message}"
        response = self.llm.invoke(prompt)
        return response.content if hasattr(response, 'content') else str(response)
