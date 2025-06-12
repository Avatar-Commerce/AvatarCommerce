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
        
        try:
            self.supabase.table("influencers").select("*").limit(1).execute()
            logger.info("Influencers table exists")
        except Exception as e:
            logger.error(f"Influencers table doesn't exist: {str(e)}")
            print("Please create the 'influencers' table manually in Supabase dashboard")

        # 2. Check if affiliate_links table exists - UPDATED SCHEMA
        try:
            self.supabase.table("affiliate_links").select("*").limit(1).execute()
            logger.info("Affiliate links table exists")
        except Exception as e:
            logger.error(f"Affiliate links table doesn't exist: {str(e)}")
            print("Please create the 'affiliate_links' table manually in Supabase dashboard with the following schema:")
            print("""
            CREATE TABLE affiliate_links (
                id TEXT PRIMARY KEY,
                influencer_id TEXT NOT NULL,
                platform TEXT NOT NULL CHECK (platform IN ('rakuten', 'amazon', 'shareasale', 'cj_affiliate')),
                affiliate_id TEXT NOT NULL,
                is_primary BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                FOREIGN KEY (influencer_id) REFERENCES influencers(id) ON DELETE CASCADE,
                UNIQUE(influencer_id, platform)
            );
            """)

        # 3. Check if chat_interactions table exists - UPDATED SCHEMA (no fan_id)
        try:
            self.supabase.table("chat_interactions").select("*").limit(1).execute()
            logger.info("Chat interactions table exists")
        except Exception as e:
            logger.error(f"Chat interactions table doesn't exist: {str(e)}")
            print("Please create the 'chat_interactions' table manually in Supabase dashboard with the following schema:")
            print("""
            CREATE TABLE chat_interactions (
                id TEXT PRIMARY KEY,
                influencer_id TEXT NOT NULL,
                session_id TEXT, -- Anonymous session ID for tracking
                user_message TEXT NOT NULL,
                bot_response TEXT NOT NULL,
                product_recommendations BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                FOREIGN KEY (influencer_id) REFERENCES influencers(id) ON DELETE CASCADE
            );
            """)

        # 4. Check if influencer_promotion_settings table exists (keep but update)
        try:
            self.supabase.table("influencer_promotion_settings").select("*").limit(1).execute()
            logger.info("Influencer promotion settings table exists")
        except Exception as e:
            logger.error(f"Influencer promotion settings table doesn't exist: {str(e)}")
            print("Please create the 'influencer_promotion_settings' table manually in Supabase dashboard")

        # 5. Check if conversation_counters table exists - UPDATED SCHEMA (no fan_id)
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
                session_id TEXT NOT NULL, -- Anonymous session ID
                message_count INTEGER NOT NULL DEFAULT 0,
                last_promotion_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                FOREIGN KEY (influencer_id) REFERENCES influencers(id) ON DELETE CASCADE,
                UNIQUE(influencer_id, session_id)
            );
            """)

        # 6. Check if influencer_products table exists (keep this)
        try:
            self.supabase.table("influencer_products").select("*").limit(1).execute()
            logger.info("Influencer products table exists")
        except Exception as e:
            logger.error(f"Influencer products table doesn't exist: {str(e)}")
            print("Please create the 'influencer_products' table manually in Supabase dashboard")

        # Add embed_configurations table check
        try:
            self.supabase.table("embed_configurations").select("*").limit(1).execute()
            logger.info("Embed configurations table exists")
        except Exception as e:
            logger.error(f"Embed configurations table doesn't exist: {str(e)}")
            print("Please create the 'embed_configurations' table manually in Supabase dashboard with the following schema:")
            print("""
            CREATE TABLE embed_configurations (
                id TEXT PRIMARY KEY,
                influencer_id TEXT NOT NULL,
                width TEXT NOT NULL DEFAULT '400px',
                height TEXT NOT NULL DEFAULT '600px',
                position TEXT NOT NULL DEFAULT 'bottom-right',
                theme TEXT NOT NULL DEFAULT 'default',
                trigger_text TEXT NOT NULL DEFAULT 'Chat with me!',
                auto_open BOOLEAN NOT NULL DEFAULT FALSE,
                custom_css TEXT,
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                FOREIGN KEY (influencer_id) REFERENCES influencers(id) ON DELETE CASCADE,
                UNIQUE(influencer_id)
            );
            """)
            
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
        
    # Embed configuration methods
    def get_embed_configuration(self, influencer_id: str) -> Optional[Dict]:
        """Get embed configuration for an influencer"""
        try:
            response = self.supabase.table('embed_configurations') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .execute()
            
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting embed configuration: {str(e)}")
            return None

    def save_embed_configuration(self, influencer_id: str, config: Dict) -> Optional[Dict]:
        """Save or update embed configuration for an influencer"""
        try:
            # Check if configuration exists
            existing_config = self.get_embed_configuration(influencer_id)
            
            config_data = {
                "influencer_id": influencer_id,
                "width": config.get("width", "400px"),
                "height": config.get("height", "600px"),
                "position": config.get("position", "bottom-right"),
                "theme": config.get("theme", "default"),
                "trigger_text": config.get("trigger_text", "Chat with me!"),
                "auto_open": config.get("auto_open", False),
                "custom_css": config.get("custom_css", ""),
                "is_active": config.get("is_active", True),
                "updated_at": 'now()'
            }
            
            if existing_config:
                # Update existing configuration
                response = self.supabase.table('embed_configurations') \
                    .update(config_data) \
                    .eq('influencer_id', influencer_id) \
                    .execute()
            else:
                # Create new configuration
                config_data["id"] = str(uuid.uuid4())
                response = self.supabase.table('embed_configurations') \
                    .insert(config_data) \
                    .execute()
            
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error saving embed configuration: {str(e)}")
            return None
    def get_influencer_with_embed_config(self, influencer_id: str) -> Optional[Dict]:
        """Get influencer data including embed configuration"""
        try:
            influencer = self.get_influencer(influencer_id)
            if not influencer:
                return None
            
            embed_config = self.get_embed_configuration(influencer_id)
            influencer['embed_config'] = embed_config
            
            return influencer
        except Exception as e:
            logger.error(f"Error getting influencer with embed config: {str(e)}")
            return None
        
    def delete_embed_configuration(self, influencer_id: str) -> bool:
        """Delete embed configuration for an influencer"""
        try:
            self.supabase.table('embed_configurations') \
                .delete() \
                .eq('influencer_id', influencer_id) \
                .execute()
            return True
        except Exception as e:
            logger.error(f"Error deleting embed configuration: {str(e)}")
            return False

    def get_embed_analytics(self, influencer_id: str, days: int = 30) -> Dict:
        """Get embed-specific analytics for an influencer"""
        try:
            from datetime import datetime, timedelta
            
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Get all chat interactions for the period
            response = self.supabase.table('chat_interactions') \
                .select('created_at, session_id') \
                .eq('influencer_id', influencer_id) \
                .gte('created_at', start_date.isoformat()) \
                .execute()
            
            interactions = response.data
            
            # Calculate metrics
            total_chats = len(interactions)
            unique_sessions = len(set([chat.get("session_id") for chat in interactions if chat.get("session_id")]))
            
            # Group by date for daily stats
            daily_stats = {}
            for interaction in interactions:
                date = interaction["created_at"][:10]  # YYYY-MM-DD
                daily_stats[date] = daily_stats.get(date, 0) + 1
            
            return {
                "total_embed_chats": total_chats,
                "unique_visitors": unique_sessions,
                "daily_stats": daily_stats,
                "avg_daily_chats": total_chats / days if days > 0 else 0,
                "period_days": days
            }
        except Exception as e:
            logger.error(f"Error getting embed analytics: {str(e)}")
            return {
                "total_embed_chats": 0,
                "unique_visitors": 0,
                "daily_stats": {},
                "avg_daily_chats": 0,
                "period_days": days
            }

    # UPDATE AFFILIATE METHODS
    def add_affiliate_link(self, influencer_id: str, platform: str, affiliate_id: str, is_primary: bool = False) -> Optional[Dict]:
        """Add an affiliate link for an influencer"""
        try:
            # Validate platform
            valid_platforms = ['rakuten', 'amazon', 'shareasale', 'cj_affiliate']
            if platform not in valid_platforms:
                logger.error(f"Invalid platform: {platform}. Must be one of {valid_platforms}")
                return None

            # If this is set as primary, unset any existing primary
            if is_primary:
                self.supabase.table('affiliate_links') \
                    .update({"is_primary": False, "updated_at": 'now()'}) \
                    .eq('influencer_id', influencer_id) \
                    .eq('is_primary', True) \
                    .execute()

            affiliate_data = {
                "id": str(uuid.uuid4()),
                "influencer_id": influencer_id,
                "platform": platform,
                "affiliate_id": affiliate_id,
                "is_primary": is_primary
            }
            
            # Use upsert to handle duplicate platform entries
            response = self.supabase.table('affiliate_links') \
                .upsert(affiliate_data, on_conflict='influencer_id,platform') \
                .execute()
                
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error adding affiliate link: {str(e)}")
            return None

    def get_affiliate_links(self, influencer_id: str, platform: str = None) -> List[Dict]:
        """Get affiliate links for an influencer, optionally filtered by platform"""
        try:
            query = self.supabase.table('affiliate_links') \
                .select('*') \
                .eq('influencer_id', influencer_id)
            
            if platform:
                query = query.eq('platform', platform)
                
            response = query.execute()
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"Error getting affiliate links: {str(e)}")
            return []

    def get_primary_affiliate_link(self, influencer_id: str) -> Optional[Dict]:
        """Get the primary affiliate link for an influencer"""
        try:
            response = self.supabase.table('affiliate_links') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .eq('is_primary', True) \
                .execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting primary affiliate link: {str(e)}")
            return None

    def set_primary_affiliate_link(self, influencer_id: str, platform: str) -> bool:
        """Set an affiliate link as primary"""
        try:
            # Unset current primary
            self.supabase.table('affiliate_links') \
                .update({"is_primary": False, "updated_at": 'now()'}) \
                .eq('influencer_id', influencer_id) \
                .execute()
            
            # Set new primary
            response = self.supabase.table('affiliate_links') \
                .update({"is_primary": True, "updated_at": 'now()'}) \
                .eq('influencer_id', influencer_id) \
                .eq('platform', platform) \
                .execute()
                
            return len(response.data) > 0
        except Exception as e:
            logger.error(f"Error setting primary affiliate link: {str(e)}")
            return False

    def delete_affiliate_link(self, influencer_id: str, platform: str) -> bool:
        """Delete an affiliate link"""
        try:
            self.supabase.table('affiliate_links') \
                .delete() \
                .eq('influencer_id', influencer_id) \
                .eq('platform', platform) \
                .execute()
            return True
        except Exception as e:
            logger.error(f"Error deleting affiliate link: {str(e)}")
            return False

    # UPDATE CONVERSATION COUNTER METHODS (replace fan_id with session_id)
    def get_conversation_counter(self, influencer_id: str, session_id: str) -> Optional[Dict]:
        """Get the conversation counter between an influencer and anonymous session"""
        try:
            response = self.supabase.table('conversation_counters') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .eq('session_id', session_id) \
                .execute()
                
            if response.data:
                return response.data[0]
            else:
                # Create new counter
                counter_id = str(uuid.uuid4())
                counter = {
                    "id": counter_id,
                    "influencer_id": influencer_id,
                    "session_id": session_id,
                    "message_count": 0,
                    "last_promotion_at": None
                }
                
                create_response = self.supabase.table('conversation_counters').insert(counter).execute()
                return create_response.data[0] if create_response.data else counter
                
        except Exception as e:
            logger.error(f"Error getting conversation counter: {str(e)}")
            return {
                "message_count": 0,
                "last_promotion_at": None
            }

    def increment_conversation_counter(self, influencer_id: str, session_id: str, was_promotion: bool = False) -> Optional[Dict]:
        """Increment the conversation counter and update last promotion time if needed"""
        try:
            # Get current counter
            counter = self.get_conversation_counter(influencer_id, session_id)
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
            
            return self.get_conversation_counter(influencer_id, session_id)
                
        except Exception as e:
            logger.error(f"Error incrementing conversation counter: {str(e)}")
            return None

    def reset_conversation_counter(self, influencer_id: str, session_id: str) -> bool:
        """Reset the conversation counter between an influencer and session"""
        try:
            # Get current counter
            counter = self.get_conversation_counter(influencer_id, session_id)
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

    # UPDATE CHAT INTERACTION LOGGING (replace fan_id with session_id)
    def log_chat_interaction(self, influencer_id: str, user_message: str, 
                            bot_response: str, product_recommendations: bool,
                            session_id: Optional[str] = None) -> Optional[Dict]:
        """Log a chat interaction"""
        try:
            interaction_data = {
                "id": str(uuid.uuid4()),
                "influencer_id": influencer_id,
                "session_id": session_id,
                "user_message": user_message,
                "bot_response": bot_response,
                "product_recommendations": product_recommendations
            }
            
            response = self.supabase.table('chat_interactions').insert(interaction_data).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error logging chat interaction: {str(e)}")
            return None
    
    def get_chat_history(self, influencer_id: str, session_id: Optional[str] = None, limit: int = 10) -> List[Dict]:
        """Get chat history for a session with an influencer"""
        try:
            query = self.supabase.table('chat_interactions') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .order('created_at', {'ascending': False}) \
                .limit(limit)
                
            if session_id:
                query = query.eq('session_id', session_id)
                
            response = query.execute()
            return response.data
        except Exception as e:
            logger.error(f"Error getting chat history: {str(e)}")
            return []