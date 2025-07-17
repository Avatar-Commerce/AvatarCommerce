import os
import uuid
import json
import math
from supabase import create_client, Client
from typing import Optional, Dict, List
import logging
from datetime import datetime, timezone

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
        """Check if tables exist using Supabase REST API"""
        
        # Check influencers table
        try:
            self.supabase.table("influencers").select("*").limit(1).execute()
            logger.info("Influencers table exists")
        except Exception as e:
            logger.error(f"Influencers table doesn't exist: {str(e)}")
            print("Please create the 'influencers' table manually in Supabase dashboard")

        # Check affiliate_links table
        try:
            self.supabase.table("affiliate_links").select("*").limit(1).execute()
            logger.info("Affiliate links table exists")
        except Exception as e:
            logger.error(f"Affiliate links table doesn't exist: {str(e)}")
            print("Please create the 'affiliate_links' table manually in Supabase dashboard")

        # Check chat_interactions table
        try:
            self.supabase.table("chat_interactions").select("*").limit(1).execute()
            logger.info("Chat interactions table exists")
        except Exception as e:
            logger.error(f"Chat interactions table doesn't exist: {str(e)}")
            print("Please create the 'chat_interactions' table manually in Supabase dashboard")

        # Check influencer_promotion_settings table
        try:
            self.supabase.table("influencer_promotion_settings").select("*").limit(1).execute()
            logger.info("Influencer promotion settings table exists")
        except Exception as e:
            logger.error(f"Influencer promotion settings table doesn't exist: {str(e)}")
            print("Please create the 'influencer_promotion_settings' table manually in Supabase dashboard")

        # Check conversation_counters table
        try:
            self.supabase.table("conversation_counters").select("*").limit(1).execute()
            logger.info("Conversation counters table exists")
        except Exception as e:
            logger.error(f"Conversation counters table doesn't exist: {str(e)}")
            print("Please create the 'conversation_counters' table manually in Supabase dashboard")

        # Check influencer_products table
        try:
            self.supabase.table("influencer_products").select("*").limit(1).execute()
            logger.info("Influencer products table exists")
        except Exception as e:
            logger.error(f"Influencer products table doesn't exist: {str(e)}")
            print("Please create the 'influencer_products' table manually in Supabase dashboard")

        # Check embed_configurations table
        try:
            self.supabase.table("embed_configurations").select("*").limit(1).execute()
            logger.info("Embed configurations table exists")
        except Exception as e:
            logger.error(f"Embed configurations table doesn't exist: {str(e)}")
            print("Please create the 'embed_configurations' table manually in Supabase dashboard")

        # Check knowledge_documents table
        try:
            self.supabase.table("knowledge_documents").select("*").limit(1).execute()
            logger.info("Knowledge documents table exists")
        except Exception as e:
            logger.error(f"Knowledge documents table doesn't exist: {str(e)}")
            print("Please create the 'knowledge_documents' table manually in Supabase dashboard")

        # Check knowledge_chunks table
        try:
            self.supabase.table("knowledge_chunks").select("*").limit(1).execute()
            logger.info("Knowledge chunks table exists")
        except Exception as e:
            logger.error(f"Knowledge chunks table doesn't exist: {str(e)}")
            print("Please create the 'knowledge_chunks' table manually in Supabase dashboard")

    # =============================================================================
    # INFLUENCER MANAGEMENT
    # =============================================================================
    
    def create_influencer(self, user_data: Dict) -> Optional[Dict]:
        """Create influencer with voice preference fields using Supabase"""
        try:
            # Set default voice if not provided
            if 'preferred_voice_id' not in user_data:
                user_data['preferred_voice_id'] = '2d5b0e6cf36f460aa7fc47e3eee4ba54'
            
            # Set timestamps
            now = datetime.now(timezone.utc).isoformat()
            user_data['created_at'] = user_data.get('created_at', now)
            user_data['updated_at'] = now
            
            # Insert into Supabase
            response = self.supabase.table('influencers').insert(user_data).execute()
            
            if response.data:
                created_user = response.data[0]
                logger.info(f"✅ Created new influencer: {user_data['username']}")
                return created_user
            else:
                logger.error("❌ No data returned from create operation")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error creating influencer: {e}")
            return None

    def get_influencer_by_username(self, username: str) -> Optional[Dict]:
        """Get influencer by username with voice preference using Supabase"""
        try:
            response = self.supabase.table('influencers') \
                .select('*') \
                .eq('username', username) \
                .execute()
            
            if response.data:
                influencer = response.data[0]
                # Ensure voice preference exists
                if not influencer.get('preferred_voice_id'):
                    influencer['preferred_voice_id'] = '2d5b0e6cf36f460aa7fc47e3eee4ba54'
                return influencer
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Error getting influencer by username: {e}")
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
            logger.error(f"Error getting influencer by email: {str(e)}")
            return None

    def get_influencer(self, influencer_id: str) -> Optional[Dict]:
        """Get influencer with proper voice preference retrieval using Supabase"""
        try:
            response = self.supabase.table('influencers') \
                .select('*') \
                .eq('id', influencer_id) \
                .execute()
            
            if response.data:
                influencer = response.data[0]
                # Ensure voice preference exists
                if not influencer.get('preferred_voice_id'):
                    influencer['preferred_voice_id'] = '2d5b0e6cf36f460aa7fc47e3eee4ba54'
                return influencer
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Error getting influencer: {e}")
            return None

    def update_influencer(self, influencer_id: str, update_data: Dict) -> bool:
        """Update influencer data with proper voice preference handling using Supabase"""
        try:
            # Add updated timestamp
            update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
            
            # Update in Supabase
            response = self.supabase.table('influencers') \
                .update(update_data) \
                .eq('id', influencer_id) \
                .execute()
            
            success = bool(response.data)
            
            if success:
                logger.info(f"✅ Successfully updated influencer {influencer_id}")
                if 'preferred_voice_id' in update_data:
                    logger.info(f"🎤 Voice preference updated to: {update_data['preferred_voice_id']}")
            else:
                logger.warning(f"⚠️ No rows affected when updating influencer {influencer_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"❌ Error updating influencer: {e}")
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

    def update_avatar_status(self, influencer_id: str, avatar_data: Dict) -> bool:
        """Update avatar status using Supabase"""
        try:
            # Extract avatar data
            update_data = {
                'updated_at': datetime.now(timezone.utc).isoformat()
            }
            
            if 'heygen_avatar_id' in avatar_data:
                update_data['heygen_avatar_id'] = avatar_data['heygen_avatar_id']
            if 'avatar_training_status' in avatar_data:
                update_data['avatar_training_status'] = avatar_data['avatar_training_status']
            if 'avatar_type' in avatar_data:
                update_data['avatar_type'] = avatar_data['avatar_type']
            
            # Update in Supabase
            response = self.supabase.table('influencers') \
                .update(update_data) \
                .eq('id', influencer_id) \
                .execute()
            
            success = bool(response.data)
            
            if success:
                logger.info(f"✅ Avatar status updated for influencer {influencer_id}")
                if 'heygen_avatar_id' in avatar_data:
                    logger.info(f"🎭 Avatar ID: {avatar_data['heygen_avatar_id']}")
                if 'avatar_training_status' in avatar_data:
                    logger.info(f"📊 Status: {avatar_data['avatar_training_status']}")
                if 'avatar_type' in avatar_data:
                    logger.info(f"🎬 Type: {avatar_data['avatar_type']}")
            
            return success
            
        except Exception as e:
            logger.error(f"❌ Error updating avatar status: {e}")
            return False

    def get_avatar_info(self, influencer_id: str) -> Optional[Dict]:
        """Get avatar information for an influencer"""
        try:
            response = self.supabase.table('influencers') \
                .select('heygen_avatar_id, heygen_asset_id, original_asset_path, avatar_training_status, avatar_created_at, avatar_ready_at') \
                .eq('id', influencer_id) \
                .execute()
            
            return response.data[0] if response.data else None
            
        except Exception as e:
            logger.error(f"Error getting avatar info: {str(e)}")
            return None

    def set_avatar_ready(self, influencer_id: str) -> bool:
        """Mark an avatar as ready for video generation"""
        try:
            updates = {
                'avatar_training_status': 'completed',
                'avatar_ready_at': datetime.now(timezone.utc).isoformat(),
                'updated_at': datetime.now(timezone.utc).isoformat()
            }
            
            response = self.supabase.table('influencers') \
                .update(updates) \
                .eq('id', influencer_id) \
                .execute()
            
            return len(response.data) > 0
            
        except Exception as e:
            logger.error(f"Error setting avatar ready: {str(e)}")
            return False

    def get_influencers_with_pending_avatars(self) -> List[Dict]:
        """Get influencers with avatars that are still training"""
        try:
            response = self.supabase.table('influencers') \
                .select('id, username, heygen_avatar_id, avatar_training_status, avatar_created_at') \
                .not_.is_('heygen_avatar_id', 'null') \
                .in_('avatar_training_status', ['pending', 'processing', 'training']) \
                .execute()
            
            return response.data
            
        except Exception as e:
            logger.error(f"Error getting pending avatars: {str(e)}")
            return []

    # =============================================================================
    # KNOWLEDGE MANAGEMENT
    # =============================================================================
    
    def get_knowledge_documents(self, influencer_id: str) -> List[Dict]:
        """Get knowledge documents for an influencer"""
        try:
            response = self.supabase.table('knowledge_documents') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .order('upload_date', desc=True) \
                .execute()
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"Error getting knowledge documents: {e}")
            return []

    def save_knowledge_document(self, document_data: Dict) -> Optional[str]:
        """Save knowledge document metadata"""
        try:
            response = self.supabase.table('knowledge_documents') \
                .insert(document_data) \
                .execute()
            return response.data[0]['id'] if response.data else None
        except Exception as e:
            logger.error(f"Error saving knowledge document: {e}")
            return None

    def delete_knowledge_document(self, document_id: str, influencer_id: str) -> bool:
        """Delete a knowledge document"""
        try:
            # First delete associated chunks
            self.supabase.table('knowledge_chunks') \
                .delete() \
                .eq('document_id', document_id) \
                .eq('influencer_id', influencer_id) \
                .execute()
            
            # Then delete the document
            response = self.supabase.table('knowledge_documents') \
                .delete() \
                .eq('id', document_id) \
                .eq('influencer_id', influencer_id) \
                .execute()
            return bool(response.data)
        except Exception as e:
            logger.error(f"Error deleting knowledge document: {e}")
            return False

    def get_personal_knowledge(self, influencer_id: str) -> Optional[Dict]:
        """Get personal knowledge information from influencer profile"""
        try:
            influencer = self.get_influencer(influencer_id)
            if not influencer:
                return None
            
            return {
                'bio': influencer.get('bio', ''),
                'expertise': influencer.get('expertise', ''),
                'personality': influencer.get('personality', '')
            }
        except Exception as e:
            logger.error(f"Error getting personal knowledge: {e}")
            return None

    def save_personal_knowledge(self, influencer_id: str, personal_data: Dict) -> bool:
        """Save personal knowledge information to influencer profile"""
        try:
            # Extract only the fields we want to update
            update_data = {}
            if 'bio' in personal_data:
                update_data['bio'] = personal_data['bio']
            if 'expertise' in personal_data:
                update_data['expertise'] = personal_data['expertise']
            if 'personality' in personal_data:
                update_data['personality'] = personal_data['personality']
            
            return self.update_influencer(influencer_id, update_data)
        except Exception as e:
            logger.error(f"Error saving personal knowledge: {e}")
            return False

    def search_knowledge_base(self, influencer_id: str, query_embedding: List[float], limit: int = 5) -> List[Dict]:
        """Search knowledge base using semantic similarity"""
        try:
            # Get all chunks for the influencer
            response = self.supabase.table('knowledge_chunks') \
                .select('*, knowledge_documents(filename)') \
                .eq('influencer_id', influencer_id) \
                .execute()
            
            chunks = response.data if response.data else []
            
            # Calculate similarities
            similarities = []
            
            for chunk in chunks:
                try:
                    if chunk['embedding']:
                        # Parse embedding from string
                        chunk_embedding = json.loads(chunk['embedding']) if isinstance(chunk['embedding'], str) else chunk['embedding']
                        
                        # Calculate cosine similarity
                        similarity = self._cosine_similarity(query_embedding, chunk_embedding)
                        
                        similarities.append({
                            'chunk_id': chunk['id'],
                            'document_id': chunk['document_id'],
                            'text': chunk['chunk_text'],
                            'similarity': float(similarity),
                            'chunk_index': chunk['chunk_index'],
                            'document_name': chunk['knowledge_documents']['filename'] if chunk['knowledge_documents'] else 'Unknown'
                        })
                        
                except Exception as embedding_error:
                    logger.error(f"Error processing embedding for chunk {chunk['id']}: {embedding_error}")
                    continue
            
            # Sort by similarity and return top results
            similarities.sort(key=lambda x: x['similarity'], reverse=True)
            return similarities[:limit]
            
        except Exception as e:
            logger.error(f"Error searching knowledge base: {e}")
            return []

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Calculate cosine similarity between two vectors"""
        try:
            dot_product = sum(a * b for a, b in zip(vec1, vec2))
            magnitude1 = math.sqrt(sum(a * a for a in vec1))
            magnitude2 = math.sqrt(sum(a * a for a in vec2))
            
            if magnitude1 == 0 or magnitude2 == 0:
                return 0
            
            return dot_product / (magnitude1 * magnitude2)
        except Exception as e:
            logger.error(f"Error calculating cosine similarity: {e}")
            return 0

    def store_chat_interaction(self, interaction_data: Dict) -> bool:
        """Store chat interaction for analytics"""
        try:
            # Add ID and timestamp if not present
            if 'id' not in interaction_data:
                interaction_data['id'] = str(uuid.uuid4())
            if 'created_at' not in interaction_data:
                interaction_data['created_at'] = datetime.now(timezone.utc).isoformat()
            
            response = self.supabase.table('chat_interactions').insert(interaction_data).execute()
            return bool(response.data)
        except Exception as e:
            logger.error(f"Error storing chat interaction: {e}")
            return False

    def get_knowledge_for_chat(self, influencer_id: str, query: str, limit: int = 3) -> Dict:
        """Get relevant knowledge for chat responses"""
        try:
            result = {
                'personal_info': None,
                'relevant_chunks': []
            }
            
            # Get personal information
            personal_info = self.get_personal_knowledge(influencer_id)
            if personal_info:
                result['personal_info'] = personal_info
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting knowledge for chat: {e}")
            return {'personal_info': None, 'relevant_chunks': []}

    # =============================================================================
    # PROMOTION SETTINGS
    # =============================================================================
    
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
                settings['updated_at'] = datetime.now(timezone.utc).isoformat()
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

    # =============================================================================
    # INFLUENCER PRODUCTS
    # =============================================================================
    
    def add_influencer_product(self, influencer_id: str, product_name: str, product_query: str, is_default: bool = False) -> Optional[Dict]:
        """Add a product for an influencer to promote"""
        try:
            # If this is the default product, unset any existing default
            if is_default:
                self.supabase.table('influencer_products') \
                    .update({"is_default": False, "updated_at": datetime.now(timezone.utc).isoformat()}) \
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
                .update({"is_default": False, "updated_at": datetime.now(timezone.utc).isoformat()}) \
                .eq('influencer_id', influencer_id) \
                .eq('is_default', True) \
                .execute()
                
            # Set the new default
            self.supabase.table('influencer_products') \
                .update({"is_default": True, "updated_at": datetime.now(timezone.utc).isoformat()}) \
                .eq('id', product_id) \
                .execute()
                
            # Update the promotion settings
            self.update_promotion_settings(influencer_id, {"default_product": product.get("product_query")})
                
            return True
                
        except Exception as e:
            logger.error(f"Error setting default product: {str(e)}")
            return False

    # =============================================================================
    # EMBED CONFIGURATIONS
    # =============================================================================
    
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
                "updated_at": datetime.now(timezone.utc).isoformat()
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
            from datetime import timedelta
            
            start_date = datetime.now(timezone.utc) - timedelta(days=days)
            
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

    # =============================================================================
    # AFFILIATE LINKS
    # =============================================================================
    
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
                    .update({"is_primary": False, "updated_at": datetime.now(timezone.utc).isoformat()}) \
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
                .update({"is_primary": False, "updated_at": datetime.now(timezone.utc).isoformat()}) \
                .eq('influencer_id', influencer_id) \
                .execute()
            
            # Set new primary
            response = self.supabase.table('affiliate_links') \
                .update({"is_primary": True, "updated_at": datetime.now(timezone.utc).isoformat()}) \
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

    # =============================================================================
    # CONVERSATION COUNTERS
    # =============================================================================
    
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
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            
            if was_promotion:
                updates["last_promotion_at"] = datetime.now(timezone.utc).isoformat()
            
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