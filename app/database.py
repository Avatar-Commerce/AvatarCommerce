import os
from supabase import create_client, Client
from typing import Optional, Dict, List
import logging
import uuid

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Database:
    def __init__(self):
        """Initialize Supabase client and tables"""
        self.supabase = create_client(
            os.getenv("SUPABASE_URL"),
            os.getenv("SUPABASE_KEY")
        )
        self.initialize_tables()

    def initialize_tables(self):
        """Create tables if they don't exist using standard REST API"""
        # Existing code here...
        
        # 5. Check if influencer_promotion_settings table exists
        try:
            self.supabase.table("influencer_promotion_settings").select("*").limit(1).execute()
            logger.info("Influencer promotion settings table exists")
        except Exception as e:
            logger.error(f"Influencer promotion settings table doesn't exist: {str(e)}")
            print("Please create the 'influencer_promotion_settings' table manually in Supabase dashboard with the following schema:")
            print("""
            CREATE TABLE influencer_promotion_settings (
                id TEXT PRIMARY KEY,
                influencer_id TEXT NOT NULL,
                promotion_frequency INTEGER NOT NULL DEFAULT 3,
                promote_at_end BOOLEAN NOT NULL DEFAULT FALSE,
                default_product TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                FOREIGN KEY (influencer_id) REFERENCES influencers(id) ON DELETE CASCADE
            );
            """)
        
        # 6. Check if conversation_counters table exists
        try:
            self.supabase.table("conversation_counters").select("*").limit(1).execute()
            logger.info("Conversation counters table exists")
        except Exception as e:
            logger.error(f"Conversation counters table doesn't exist: {str(e)}")
            print("Please create the 'conversation_counters' table manually in Supabase dashboard with the following schema:")
            print("""
            CREATE TABLE conversation_counters (
                id TEXT PRIMARY KEY,
                influencer_id TEXT NOT NULL,
                fan_id TEXT NOT NULL,
                message_count INTEGER NOT NULL DEFAULT 0,
                last_promotion_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                FOREIGN KEY (influencer_id) REFERENCES influencers(id) ON DELETE CASCADE,
                FOREIGN KEY (fan_id) REFERENCES fans(id) ON DELETE CASCADE,
                UNIQUE(influencer_id, fan_id)
            );
            """)
        
        # 7. Check if influencer_products table exists
        try:
            self.supabase.table("influencer_products").select("*").limit(1).execute()
            logger.info("Influencer products table exists")
        except Exception as e:
            logger.error(f"Influencer products table doesn't exist: {str(e)}")
            print("Please create the 'influencer_products' table manually in Supabase dashboard with the following schema:")
            print("""
            CREATE TABLE influencer_products (
                id TEXT PRIMARY KEY,
                influencer_id TEXT NOT NULL,
                product_name TEXT NOT NULL,
                product_query TEXT NOT NULL,
                is_default BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                FOREIGN KEY (influencer_id) REFERENCES influencers(id) ON DELETE CASCADE
            );
            """)

    # Promotion Settings Methods
    def get_promotion_settings(self, influencer_id: str) -> Optional[Dict]:
        """Get promotion settings for an influencer"""
        try:
            response = self.supabase.table('influencer_promotion_settings') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .execute()
            
            # Return the first result or create default settings if none exist
            if response.data:
                return response.data[0]
            else:
                # Create default settings
                settings_id = str(uuid.uuid4())
                settings = {
                    "id": settings_id,
                    "influencer_id": influencer_id,
                    "promotion_frequency": 3,  # Default: promote every 3 messages
                    "promote_at_end": False,   # Default: don't promote at the end of every message
                    "default_product": None    # No default product
                }
                
                create_response = self.supabase.table('influencer_promotion_settings').insert(settings).execute()
                return create_response.data[0] if create_response.data else settings
                
        except Exception as e:
            logger.error(f"Error getting promotion settings: {str(e)}")
            # Return default settings if error
            return {
                "promotion_frequency": 3,
                "promote_at_end": False,
                "default_product": None
            }

    def update_promotion_settings(self, influencer_id: str, settings: Dict) -> bool:
        """Update promotion settings for an influencer"""
        try:
            # Get current settings or create if don't exist
            current_settings = self.get_promotion_settings(influencer_id)
            settings_id = current_settings.get("id")
            
            if settings_id:
                # Update existing settings
                settings['updated_at'] = 'now()'
                response = self.supabase.table('influencer_promotion_settings') \
                    .update(settings) \
                    .eq('id', settings_id) \
                    .execute()
            else:
                # Create new settings
                settings_id = str(uuid.uuid4())
                settings["id"] = settings_id
                settings["influencer_id"] = influencer_id
                response = self.supabase.table('influencer_promotion_settings').insert(settings).execute()
                
            return True
        except Exception as e:
            logger.error(f"Error updating promotion settings: {str(e)}")
            return False

    # Conversation Counter Methods
    def get_conversation_counter(self, influencer_id: str, fan_id: str) -> Optional[Dict]:
        """Get the conversation counter between an influencer and fan"""
        try:
            response = self.supabase.table('conversation_counters') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .eq('fan_id', fan_id) \
                .execute()
                
            if response.data:
                return response.data[0]
            else:
                # Create new counter
                counter_id = str(uuid.uuid4())
                counter = {
                    "id": counter_id,
                    "influencer_id": influencer_id,
                    "fan_id": fan_id,
                    "message_count": 0,
                    "last_promotion_at": None
                }
                
                create_response = self.supabase.table('conversation_counters').insert(counter).execute()
                return create_response.data[0] if create_response.data else counter
                
        except Exception as e:
            logger.error(f"Error getting conversation counter: {str(e)}")
            # Return default counter if error
            return {
                "message_count": 0,
                "last_promotion_at": None
            }

    def increment_conversation_counter(self, influencer_id: str, fan_id: str, was_promotion: bool = False) -> Optional[Dict]:
        """Increment the conversation counter and update last promotion time if needed"""
        try:
            # Get current counter
            counter = self.get_conversation_counter(influencer_id, fan_id)
            counter_id = counter.get("id")
            
            updates = {
                "message_count": counter.get("message_count", 0) + 1,
                "updated_at": 'now()'
            }
            
            if was_promotion:
                updates["last_promotion_at"] = 'now()'
            
            if counter_id:
                # Update existing counter
                response = self.supabase.table('conversation_counters') \
                    .update(updates) \
                    .eq('id', counter_id) \
                    .execute()
                    
                if response.data:
                    return response.data[0]
            else:
                # Create new counter
                counter_id = str(uuid.uuid4())
                counter = {
                    "id": counter_id,
                    "influencer_id": influencer_id,
                    "fan_id": fan_id,
                    "message_count": 1,
                    "last_promotion_at": 'now()' if was_promotion else None
                }
                
                create_response = self.supabase.table('conversation_counters').insert(counter).execute()
                if create_response.data:
                    return create_response.data[0]
            
            # If we reach here, something went wrong, so check the counter again
            return self.get_conversation_counter(influencer_id, fan_id)
                
        except Exception as e:
            logger.error(f"Error incrementing conversation counter: {str(e)}")
            return None

    def reset_conversation_counter(self, influencer_id: str, fan_id: str) -> bool:
        """Reset the conversation counter between an influencer and fan"""
        try:
            # Get current counter
            counter = self.get_conversation_counter(influencer_id, fan_id)
            counter_id = counter.get("id")
            
            if counter_id:
                # Update existing counter
                updates = {
                    "message_count": 0,
                    "last_promotion_at": None,
                    "updated_at": 'now()'
                }
                
                self.supabase.table('conversation_counters') \
                    .update(updates) \
                    .eq('id', counter_id) \
                    .execute()
                    
            return True
        except Exception as e:
            logger.error(f"Error resetting conversation counter: {str(e)}")
            return False

    # Influencer Products Methods
    def add_influencer_product(self, influencer_id: str, product_name: str, product_query: str, is_default: bool = False) -> Optional[Dict]:
        """Add a product for an influencer to promote"""
        try:
            # If this is the default product, unset any existing default
            if is_default:
                self.supabase.table('influencer_products') \
                    .update({"is_default": False, "updated_at": 'now()'}) \
                    .eq('influencer_id', influencer_id) \
                    .eq('is_default', True) \
                    .execute()
                    
                # Also update the promotion settings
                self.update_promotion_settings(influencer_id, {"default_product": product_query})
            
            # Create new product
            product_id = str(uuid.uuid4())
            product = {
                "id": product_id,
                "influencer_id": influencer_id,
                "product_name": product_name,
                "product_query": product_query,
                "is_default": is_default
            }
            
            response = self.supabase.table('influencer_products').insert(product).execute()
            return response.data[0] if response.data else None
                
        except Exception as e:
            logger.error(f"Error adding influencer product: {str(e)}")
            return None

    def get_influencer_products(self, influencer_id: str) -> List[Dict]:
        """Get all products for an influencer"""
        try:
            response = self.supabase.table('influencer_products') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .execute()
                
            return response.data if response.data else []
                
        except Exception as e:
            logger.error(f"Error getting influencer products: {str(e)}")
            return []

    def get_default_product(self, influencer_id: str) -> Optional[Dict]:
        """Get the default product for an influencer"""
        try:
            response = self.supabase.table('influencer_products') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .eq('is_default', True) \
                .execute()
                
            return response.data[0] if response.data else None
                
        except Exception as e:
            logger.error(f"Error getting default product: {str(e)}")
            return None

    def delete_influencer_product(self, product_id: str) -> bool:
        """Delete a product"""
        try:
            self.supabase.table('influencer_products') \
                .delete() \
                .eq('id', product_id) \
                .execute()
                
            return True
                
        except Exception as e:
            logger.error(f"Error deleting influencer product: {str(e)}")
            return False

    def set_default_product(self, product_id: str) -> bool:
        """Set a product as the default"""
        try:
            # Get the product to check influencer_id
            response = self.supabase.table('influencer_products') \
                .select('*') \
                .eq('id', product_id) \
                .execute()
                
            if not response.data:
                return False
                
            product = response.data[0]
            influencer_id = product.get("influencer_id")
            
            # Unset any existing default
            self.supabase.table('influencer_products') \
                .update({"is_default": False, "updated_at": 'now()'}) \
                .eq('influencer_id', influencer_id) \
                .eq('is_default', True) \
                .execute()
                
            # Set the new default
            self.supabase.table('influencer_products') \
                .update({"is_default": True, "updated_at": 'now()'}) \
                .eq('id', product_id) \
                .execute()
                
            # Update the promotion settings
            self.update_promotion_settings(influencer_id, {"default_product": product.get("product_query")})
                
            return True
                
        except Exception as e:
            logger.error(f"Error setting default product: {str(e)}")
            return False
        
    # Fan management methods
    def create_fan(self, fan_data: Dict) -> Optional[Dict]:
        """Create a new fan account"""
        required_fields = {'id', 'username', 'email', 'password_hash'}
        if not all(field in fan_data for field in required_fields):
            logger.error(f"Missing required fields: {required_fields}")
            return None
        
        try:
            response = self.supabase.table('fans').insert(fan_data).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error creating fan: {str(e)}")
            return None
    
    def get_fan_by_username(self, username: str) -> Optional[Dict]:
        """Get fan by username"""
        try:
            response = self.supabase.table('fans') \
                .select('*') \
                .eq('username', username) \
                .execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting fan: {str(e)}")
            return None
    
    def get_fan_by_email(self, email: str) -> Optional[Dict]:
        """Get fan by email"""
        try:
            response = self.supabase.table('fans') \
                .select('*') \
                .eq('email', email) \
                .execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting fan: {str(e)}")
            return None
    
    def get_fan(self, fan_id: str) -> Optional[Dict]:
        """Get fan by ID"""
        try:
            response = self.supabase.table('fans') \
                .select('*') \
                .eq('id', fan_id) \
                .execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting fan: {str(e)}")
            return None
    
    # Influencer management methods
    def create_influencer(self, influencer_data: Dict) -> Optional[Dict]:
        """Create a new influencer with authentication credentials"""
        required_fields = {'id', 'username', 'email', 'password_hash'}
        if not all(field in influencer_data for field in required_fields):
            logger.error(f"Missing required fields: {required_fields}")
            return None

        # Generate chat page URL
        username = influencer_data['username']
        influencer_data['chat_page_url'] = f"/chat/{username}"
        
        try:
            response = self.supabase.table('influencers').insert(influencer_data).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error creating influencer: {str(e)}")
            return None

    def get_influencer_by_username(self, username: str) -> Optional[Dict]:
        """Get influencer by username"""
        try:
            response = self.supabase.table('influencers') \
                .select('*') \
                .eq('username', username) \
                .execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting influencer: {str(e)}")
            return None

    def get_influencer_by_email(self, email: str) -> Optional[Dict]:
        """Get influencer by email"""
        try:
            response = self.supabase.table('influencers') \
                .select('*') \
                .eq('email', email) \
                .execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting influencer: {str(e)}")
            return None

    def get_influencer(self, influencer_id: str) -> Optional[Dict]:
        """Get influencer by ID"""
        try:
            response = self.supabase.table('influencers') \
                .select('*') \
                .eq('id', influencer_id) \
                .execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting influencer: {str(e)}")
            return None

    def update_influencer(self, influencer_id: str, updates: Dict) -> bool:
        """Update influencer data"""
        if not updates:
            return False

        try:
            updates['updated_at'] = 'now()'
            response = self.supabase.table('influencers') \
                .update(updates) \
                .eq('id', influencer_id) \
                .execute()
            return True
        except Exception as e:
            logger.error(f"Error updating influencer: {str(e)}")
            return False

    def delete_influencer(self, influencer_id: str) -> bool:
        """Delete an influencer"""
        try:
            response = self.supabase.table('influencers') \
                .delete() \
                .eq('id', influencer_id) \
                .execute()
            return True
        except Exception as e:
            logger.error(f"Error deleting influencer: {str(e)}")
            return False

    def get_all_influencers(self) -> List[Dict]:
        """Get all influencers"""
        try:
            response = self.supabase.table('influencers') \
                .select('*') \
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error getting all influencers: {str(e)}")
            return []

    # Avatar management methods
    def store_original_asset(self, influencer_id: str, file_bytes: bytes, file_name: str) -> Optional[str]:
        try:
            bucket_name = "influencer-assets"  # Changed to hyphen
            file_path = f"original_avatars/{influencer_id}/{file_name}"
            self.supabase.storage.from_(bucket_name).upload(file_path, file_bytes)
            self.update_influencer(influencer_id, {'original_asset_path': file_path})
            return file_path
        except Exception as e:
            logger.error(f"Error storing asset: {str(e)}")
            return None

    def get_original_asset(self, influencer_id: str) -> Optional[bytes]:
        """Retrieve original avatar file"""
        try:
            influencer = self.get_influencer(influencer_id)
            if not influencer or not influencer.get('original_asset_path'):
                return None
                
            bucket_name = "influencer-assets"
            file_path = influencer['original_asset_path']
            
            return self.supabase.storage.from_(bucket_name).download(file_path)
        except Exception as e:
            logger.error(f"Error retrieving original asset: {str(e)}")
            return None
            
    # Affiliate management methods
    def add_affiliate_link(self, influencer_id: str, platform: str, affiliate_id: str) -> Optional[Dict]:
        """Add an affiliate link for an influencer"""
        try:
            affiliate_data = {
                "id": str(uuid.uuid4()),
                "influencer_id": influencer_id,
                "platform": platform,
                "affiliate_id": affiliate_id
            }
            
            response = self.supabase.table('affiliate_links').insert(affiliate_data).execute()
            
            # Also update the influencer's default affiliate_id if none exists
            influencer = self.get_influencer(influencer_id)
            if not influencer.get('affiliate_id'):
                self.update_influencer(influencer_id, {'affiliate_id': affiliate_id})
                
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error adding affiliate link: {str(e)}")
            return None
            
    def get_affiliate_links(self, influencer_id: str) -> List[Dict]:
        """Get all affiliate links for an influencer"""
        try:
            response = self.supabase.table('affiliate_links') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error getting affiliate links: {str(e)}")
            return []
            
    def get_primary_affiliate_id(self, influencer_id: str) -> Optional[str]:
        """Get the primary affiliate ID for an influencer"""
        try:
            influencer = self.get_influencer(influencer_id)
            return influencer.get('affiliate_id') if influencer else None
        except Exception as e:
            logger.error(f"Error getting primary affiliate ID: {str(e)}")
            return None
            
    # Chat interaction methods
    def log_chat_interaction(self, influencer_id: str, user_message: str, 
                            bot_response: str, product_recommendations: bool,
                            fan_id: Optional[str] = None) -> Optional[Dict]:
        """Log a chat interaction"""
        try:
            interaction_data = {
                "id": str(uuid.uuid4()),
                "influencer_id": influencer_id,
                "fan_id": fan_id,
                "user_message": user_message,
                "bot_response": bot_response,
                "product_recommendations": product_recommendations
            }
            
            response = self.supabase.table('chat_interactions').insert(interaction_data).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error logging chat interaction: {str(e)}")
            return None
    
    def get_chat_history(self, influencer_id: str, fan_id: Optional[str] = None, limit: int = 10) -> List[Dict]:
        """Get chat history for a fan with an influencer"""
        try:
            query = self.supabase.table('chat_interactions') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .order('created_at', {'ascending': False}) \
                .limit(limit)
                
            if fan_id:
                query = query.eq('fan_id', fan_id)
                
            response = query.execute()
            return response.data
        except Exception as e:
            logger.error(f"Error getting chat history: {str(e)}")
            return []