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
            # Core required fields
            core_data = {
                'id': user_data.get('id', str(uuid.uuid4())),
                'username': user_data['username'],
                'email': user_data['email'],
                'password_hash': user_data['password_hash'],
                'bio': user_data.get('bio', ''),
                'created_at': user_data.get('created_at', datetime.now(timezone.utc).isoformat()),
                'updated_at': datetime.now(timezone.utc).isoformat()
            }
            
            # Optional fields - only add if they don't cause column errors
            optional_fields = {
                'preferred_voice_id': '2d5b0e6cf36f460aa7fc47e3eee4ba54',
                'expertise': user_data.get('expertise', ''),
                'personality': user_data.get('personality', ''),
                'avatar_training_status': 'none',
                'avatar_type': 'none'
            }
            
            # Try with all fields first
            try:
                final_data = {**core_data, **optional_fields}
                response = self.supabase.table('influencers').insert(final_data).execute()
                
                if response.data:
                    created_user = response.data[0]
                    logger.info(f"✅ Created new influencer with full schema: {user_data['username']}")
                    return created_user
                    
            except Exception as schema_error:
                # If that fails, try with just core fields
                logger.warning(f"⚠️ Full schema failed, trying core fields only: {schema_error}")
                
                response = self.supabase.table('influencers').insert(core_data).execute()
                
                if response.data:
                    created_user = response.data[0]
                    logger.info(f"✅ Created new influencer with core schema: {user_data['username']}")
                    
                    # Try to update with optional fields one by one
                    influencer_id = created_user['id']
                    for field, value in optional_fields.items():
                        try:
                            self.supabase.table('influencers') \
                                .update({field: value}) \
                                .eq('id', influencer_id) \
                                .execute()
                        except Exception as field_error:
                            logger.warning(f"⚠️ Could not set {field}: {field_error}")
                    
                    # Return the created user (will be fetched fresh if needed)
                    return created_user
                else:
                    logger.error("❌ No data returned from core create operation")
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

    def update_avatar_status(self, influencer_id, avatar_data):
        """Enhanced avatar status update with better error handling"""
        try:
            logger.info(f"💾 Updating avatar status for influencer: {influencer_id}")
            
            # Add timestamp
            avatar_data['updated_at'] = datetime.now(timezone.utc).isoformat()
            
            # Update the influencer record
            result = self.supabase.table('influencers').update(avatar_data).eq('id', influencer_id).execute()
            
            if result.data and len(result.data) > 0:
                logger.info("✅ Avatar status updated successfully")
                return True
            else:
                logger.error("❌ Avatar status update failed - no rows affected")
                return False
                
        except Exception as e:
            logger.error(f"❌ Database error updating avatar status: {e}")
            return False

    def get_influencer_by_username(self, username):
        """FIXED: Get influencer by username with case-insensitive search"""
        try:
            # Convert to lowercase for consistent lookup
            clean_username = username.lower().strip()
            
            response = self.supabase.table('influencers')\
                .select('*')\
                .ilike('username', clean_username)\
                .limit(1)\
                .execute()
            
            if response.data and len(response.data) > 0:
                user = response.data[0]
                print(f"✅ Found user: {user['username']}")
                return user
            else:
                print(f"❌ User not found: {username}")
                return None
                
        except Exception as e:
            print(f"❌ Database error getting user by username: {e}")
            return None

    def get_influencer_by_email(self, email):
        """FIXED: Get influencer by email with case-insensitive search"""
        try:
            # Convert to lowercase for consistent lookup
            clean_email = email.lower().strip()
            
            response = self.supabase.table('influencers')\
                .select('*')\
                .ilike('email', clean_email)\
                .limit(1)\
                .execute()
            
            if response.data and len(response.data) > 0:
                return response.data[0]
            else:
                return None
                
        except Exception as e:
            print(f"❌ Database error getting user by email: {e}")
            return None

    def store_chat_interaction(self, interaction_data):
        """Store chat interaction for analytics"""
        try:
            response = self.supabase.table('chat_interactions')\
                .insert(interaction_data)\
                .execute()
            
            if response.data:
                print(f"✅ Chat interaction stored: {interaction_data['session_id']}")
                return response.data[0]
            else:
                print("❌ Failed to store chat interaction")
                return None
                
        except Exception as e:
            print(f"❌ Database error storing chat interaction: {e}")
            return None

    def get_affiliate_links(self, influencer_id: str) -> List[Dict]:
        """Get all affiliate links for an influencer"""
        try:
            response = self.supabase.table('affiliate_links') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .eq('is_active', True) \
                .execute()
            
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"Error getting affiliate links: {e}")
            return []

    def get_affiliate_link_by_platform(self, influencer_id: str, platform: str) -> Optional[Dict]:
        """Get a specific affiliate link by platform"""
        try:
            response = self.supabase.table('affiliate_links') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .eq('platform', platform) \
                .limit(1) \
                .execute()
            
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error getting affiliate link by platform: {e}")
            return None

    def create_affiliate_link(self, affiliate_data: Dict) -> bool:
        """Create a new affiliate link"""
        try:
            # Ensure ID is a string (not UUID object)
            if 'id' in affiliate_data:
                affiliate_data['id'] = str(affiliate_data['id'])
            
            # Ensure influencer_id is a string
            if 'influencer_id' in affiliate_data:
                affiliate_data['influencer_id'] = str(affiliate_data['influencer_id'])
            
            response = self.supabase.table('affiliate_links') \
                .insert(affiliate_data) \
                .execute()
            
            return bool(response.data)
        except Exception as e:
            logger.error(f"Error creating affiliate link: {e}")
            print(f"Affiliate data causing error: {affiliate_data}")  # Debug info
            return False

    def update_affiliate_link(self, influencer_id: str, platform: str, update_data: Dict) -> bool:
        """Update an affiliate link"""
        try:
            response = self.supabase.table('affiliate_links') \
                .update(update_data) \
                .eq('influencer_id', str(influencer_id)) \
                .eq('platform', platform) \
                .execute()
            
            return bool(response.data)
        except Exception as e:
            logger.error(f"Error updating affiliate link: {e}")
            return False

    def delete_affiliate_link(self, influencer_id: str, platform: str) -> bool:
        """Delete an affiliate link"""
        try:
            response = self.supabase.table('affiliate_links') \
                .delete() \
                .eq('influencer_id', str(influencer_id)) \
                .eq('platform', platform) \
                .execute()
            
            return bool(response.data)
        except Exception as e:
            logger.error(f"Error deleting affiliate link: {e}")
            return False

    def get_personal_knowledge(self, influencer_id):
        """Get influencer's personal knowledge (bio, expertise, personality)"""
        try:
            response = self.supabase.table('influencers') \
                .select('bio, expertise, personality') \
                .eq('id', influencer_id) \
                .execute()
            
            if response.data:
                return response.data[0]
            return None
            
        except Exception as e:
            print(f"Error getting personal knowledge: {e}")
            return None

    def get_knowledge_documents(self, influencer_id):
        """Get all knowledge documents for an influencer"""
        try:
            response = self.supabase.table('knowledge_documents') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .eq('is_processed', True) \
                .execute()
            
            return response.data if response.data else []
            
        except Exception as e:
            print(f"Error getting knowledge documents: {e}")
            return []

    def search_knowledge_base(self, influencer_id, query_embedding, limit=5):
        """Search knowledge base using semantic similarity (simplified version)"""
        try:
            # Get all knowledge chunks for the influencer
            response = self.supabase.table('knowledge_chunks') \
                .select('*, knowledge_documents(filename)') \
                .eq('influencer_id', influencer_id) \
                .execute()
            
            chunks = response.data if response.data else []
            
            # For simplified version, just return recent chunks
            # In production, you'd calculate actual semantic similarity
            return [{
                'text': chunk['chunk_text'],
                'document_name': chunk['knowledge_documents']['filename'] if chunk['knowledge_documents'] else 'Document',
                'similarity': 0.7,  # Placeholder similarity score
                'chunk_index': chunk['chunk_index']
            } for chunk in chunks[:limit]]
            
        except Exception as e:
            print(f"Error searching knowledge base: {e}")
            return []

    def get_affiliate_links(self, influencer_id):
        """Get all affiliate links for an influencer"""
        try:
            response = self.supabase.table('affiliate_links') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .execute()
            
            return response.data if response.data else []
            
        except Exception as e:
            print(f"Error getting affiliate links: {e}")
            return []

    def get_affiliate_link_by_platform(self, influencer_id, platform):
        """Get specific affiliate link by platform"""
        try:
            response = self.supabase.table('affiliate_links') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .eq('platform', platform) \
                .execute()
            
            return response.data[0] if response.data else None
            
        except Exception as e:
            print(f"Error getting affiliate link: {e}")
            return None

    def create_affiliate_link(self, affiliate_data):
        """Create new affiliate link"""
        try:
            response = self.supabase.table('affiliate_links') \
                .insert(affiliate_data) \
                .execute()
            
            return bool(response.data)
            
        except Exception as e:
            print(f"Error creating affiliate link: {e}")
            return False

    def update_affiliate_link(self, influencer_id, platform, update_data):
        """Update affiliate link"""
        try:
            response = self.supabase.table('affiliate_links') \
                .update(update_data) \
                .eq('influencer_id', influencer_id) \
                .eq('platform', platform) \
                .execute()
            
            return bool(response.data)
            
        except Exception as e:
            print(f"Error updating affiliate link: {e}")
            return False

    def delete_affiliate_link(self, influencer_id, platform):
        """Delete affiliate link"""
        try:
            response = self.supabase.table('affiliate_links') \
                .delete() \
                .eq('influencer_id', influencer_id) \
                .eq('platform', platform) \
                .execute()
            
            return bool(response.data)
            
        except Exception as e:
            print(f"Error deleting affiliate link: {e}")
            return False

    def store_chat_interaction(self, interaction_data):
        """Store chat interaction for analytics"""
        try:
            response = self.supabase.table('chat_interactions') \
                .insert(interaction_data) \
                .execute()
            
            return bool(response.data)
            
        except Exception as e:
            print(f"Error storing chat interaction: {e}")
            return False

    def update_avatar_status(self, influencer_id, avatar_data):
        """Update influencer's avatar status and information"""
        try:
            update_data = {
                'updated_at': datetime.now(timezone.utc).isoformat(),
                **avatar_data
            }
            
            response = self.supabase.table('influencers') \
                .update(update_data) \
                .eq('id', influencer_id) \
                .execute()
            
            return bool(response.data)
            
        except Exception as e:
            print(f"Error updating avatar status: {e}")
            return False

    def get_chat_analytics(self, influencer_id, days=30):
        """Get chat analytics for dashboard"""
        try:
            from datetime import timedelta
            start_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            response = self.supabase.table('chat_interactions') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .gte('created_at', start_date.isoformat()) \
                .execute()
            
            interactions = response.data if response.data else []
            
            # Calculate metrics
            total_chats = len(interactions)
            unique_sessions = len(set([chat.get("session_id") for chat in interactions if chat.get("session_id")]))
            video_responses = len([chat for chat in interactions if chat.get('has_video')])
            audio_responses = len([chat for chat in interactions if chat.get('has_audio')])
            product_recommendations = len([chat for chat in interactions if chat.get('products_included')])
            
            return {
                'total_chats': total_chats,
                'unique_sessions': unique_sessions,
                'video_responses': video_responses,
                'audio_responses': audio_responses,
                'product_recommendations': product_recommendations,
                'knowledge_enhanced_responses': len([chat for chat in interactions if chat.get('knowledge_enhanced')])
            }
            
        except Exception as e:
            print(f"Error getting chat analytics: {e}")
            return {
                'total_chats': 0,
                'unique_sessions': 0,
                'video_responses': 0,
                'audio_responses': 0,
                'product_recommendations': 0,
                'knowledge_enhanced_responses': 0
            }

    def save_knowledge_document(self, document_data: Dict) -> Optional[str]:
        """FIXED: Save knowledge document metadata with proper error handling"""
        try:
            # Ensure all required fields are present
            required_fields = ['id', 'influencer_id', 'filename', 'safe_filename', 'content_type', 'file_size']
            for field in required_fields:
                if field not in document_data:
                    raise ValueError(f"Missing required field: {field}")
            
            # Add timestamps if not present
            if 'created_at' not in document_data:
                document_data['created_at'] = datetime.now(timezone.utc).isoformat()
            if 'updated_at' not in document_data:
                document_data['updated_at'] = datetime.now(timezone.utc).isoformat()
            
            response = self.supabase.table('knowledge_documents') \
                .insert(document_data) \
                .execute()
            
            if response.data and len(response.data) > 0:
                logger.info(f"✅ Knowledge document saved: {document_data['filename']}")
                return response.data[0]['id']
            else:
                logger.error(f"❌ Failed to save knowledge document: {document_data['filename']}")
                return None
                
        except Exception as e:
            logger.error(f"Error saving knowledge document: {e}")
            return None

    def get_knowledge_documents(self, influencer_id: str) -> List[Dict]:
        """FIXED: Get all knowledge documents for an influencer"""
        try:
            response = self.supabase.table('knowledge_documents') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .order('created_at', desc=True) \
                .execute()
            
            documents = response.data if response.data else []
            logger.info(f"📚 Retrieved {len(documents)} knowledge documents for influencer {influencer_id}")
            return documents
            
        except Exception as e:
            logger.error(f"Error getting knowledge documents: {e}")
            return []

    def search_knowledge_base(self, influencer_id: str, query_embedding: List[float], limit: int = 5) -> List[Dict]:
        """FIXED: Search knowledge base using semantic similarity with better error handling"""
        try:
            # Get all chunks for the influencer
            response = self.supabase.table('knowledge_chunks') \
                .select('*, knowledge_documents(filename)') \
                .eq('influencer_id', influencer_id) \
                .execute()
            
            chunks = response.data if response.data else []
            logger.info(f"🔍 Found {len(chunks)} knowledge chunks for search")
            
            if not chunks:
                return []
            
            # Calculate similarities
            similarities = []
            
            for chunk in chunks:
                try:
                    if chunk.get('embedding'):
                        # Parse embedding from string with multiple fallback methods
                        chunk_embedding = None
                        
                        # Try different parsing methods
                        embedding_str = chunk['embedding']
                        if isinstance(embedding_str, str):
                            try:
                                # Try JSON parsing first
                                chunk_embedding = json.loads(embedding_str)
                            except json.JSONDecodeError:
                                try:
                                    # Try eval as fallback (less secure but may work)
                                    chunk_embedding = eval(embedding_str)
                                except:
                                    logger.warning(f"Could not parse embedding for chunk {chunk.get('id', 'unknown')}")
                                    continue
                        elif isinstance(embedding_str, list):
                            chunk_embedding = embedding_str
                        else:
                            logger.warning(f"Unknown embedding format for chunk {chunk.get('id', 'unknown')}")
                            continue
                        
                        if chunk_embedding and len(chunk_embedding) == len(query_embedding):
                            # Calculate cosine similarity
                            similarity = self._cosine_similarity(query_embedding, chunk_embedding)
                            
                            if similarity > 0.1:  # Only include chunks with some relevance
                                similarities.append({
                                    'chunk_id': chunk.get('id'),
                                    'document_id': chunk.get('document_id'),
                                    'text': chunk.get('chunk_text', ''),
                                    'similarity': float(similarity),
                                    'chunk_index': chunk.get('chunk_index', 0),
                                    'document_name': chunk.get('knowledge_documents', {}).get('filename', 'Unknown') if chunk.get('knowledge_documents') else 'Unknown'
                                })
                            
                except Exception as embedding_error:
                    logger.error(f"Error processing embedding for chunk {chunk.get('id', 'unknown')}: {embedding_error}")
                    continue
            
            # Sort by similarity and return top results
            similarities.sort(key=lambda x: x['similarity'], reverse=True)
            top_results = similarities[:limit]
            
            logger.info(f"🎯 Knowledge search returned {len(top_results)} relevant chunks")
            for result in top_results[:3]:  # Log top 3 for debugging
                logger.info(f"   - {result['document_name']}: {result['similarity']:.3f} - {result['text'][:50]}...")
            
            return top_results
            
        except Exception as e:
            logger.error(f"Error searching knowledge base: {e}")
            return []

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """FIXED: Calculate cosine similarity between two vectors with better error handling"""
        try:
            if len(vec1) != len(vec2):
                logger.warning(f"Vector length mismatch: {len(vec1)} vs {len(vec2)}")
                return 0.0
            
            dot_product = sum(a * b for a, b in zip(vec1, vec2))
            magnitude1 = math.sqrt(sum(a * a for a in vec1))
            magnitude2 = math.sqrt(sum(a * a for a in vec2))
            
            if magnitude1 == 0 or magnitude2 == 0:
                return 0.0
            
            similarity = dot_product / (magnitude1 * magnitude2)
            
            # Ensure result is between -1 and 1
            return max(-1.0, min(1.0, similarity))
            
        except Exception as e:
            logger.error(f"Error calculating cosine similarity: {e}")
            return 0.0

    def get_personal_knowledge(self, influencer_id: str) -> Optional[Dict]:
        """FIXED: Get personal knowledge information from influencer profile"""
        try:
            influencer = self.get_influencer(influencer_id)
            if not influencer:
                logger.warning(f"Influencer not found: {influencer_id}")
                return None
            
            personal_knowledge = {
                'bio': influencer.get('bio', ''),
                'expertise': influencer.get('expertise', ''),
                'personality': influencer.get('personality', '')
            }
            
            # Check if we have any personal knowledge
            has_knowledge = any(personal_knowledge.values())
            
            if has_knowledge:
                logger.info(f"✅ Personal knowledge retrieved for {influencer_id}")
                return personal_knowledge
            else:
                logger.info(f"📝 No personal knowledge found for {influencer_id}")
                return None
            
        except Exception as e:
            logger.error(f"Error getting personal knowledge: {e}")
            return None

    def create_affiliate_link(self, affiliate_data: Dict) -> bool:
        """FIXED: Create affiliate link with proper validation"""
        try:
            # Validate required fields
            required_fields = ['id', 'influencer_id', 'platform', 'affiliate_id']
            for field in required_fields:
                if field not in affiliate_data:
                    raise ValueError(f"Missing required field: {field}")
            
            # Add timestamps if not present
            if 'created_at' not in affiliate_data:
                affiliate_data['created_at'] = datetime.now(timezone.utc).isoformat()
            if 'updated_at' not in affiliate_data:
                affiliate_data['updated_at'] = datetime.now(timezone.utc).isoformat()
            
            # Set default values
            if 'is_active' not in affiliate_data:
                affiliate_data['is_active'] = True
            
            response = self.supabase.table('affiliate_links') \
                .insert(affiliate_data) \
                .execute()
            
            if response.data and len(response.data) > 0:
                logger.info(f"✅ Affiliate link created: {affiliate_data['platform']} for {affiliate_data['influencer_id']}")
                return True
            else:
                logger.error(f"❌ Failed to create affiliate link")
                return False
                
        except Exception as e:
            logger.error(f"Error creating affiliate link: {e}")
            return False

    def get_affiliate_link_by_platform(self, influencer_id: str, platform: str) -> Optional[Dict]:
        """FIXED: Get a specific affiliate link by platform with enhanced credential retrieval"""
        try:
            response = self.supabase.table('affiliate_links') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .eq('platform', platform) \
                .eq('is_active', True) \
                .limit(1) \
                .execute()
            
            if response.data and len(response.data) > 0:
                affiliate_link = response.data[0]
                
                # FIXED: Add platform-specific credential mapping for affiliate service
                # The affiliate service expects specific field names
                enhanced_link = dict(affiliate_link)
                
                if platform == 'amazon':
                    enhanced_link['amazon_access_key'] = affiliate_link.get('amazon_access_key', '')
                    enhanced_link['amazon_secret_key'] = affiliate_link.get('amazon_secret_key', '')
                    enhanced_link['partner_tag'] = affiliate_link.get('affiliate_id', '')
                    
                elif platform == 'rakuten':
                    enhanced_link['client_id'] = affiliate_link.get('rakuten_client_id', affiliate_link.get('client_id', ''))
                    enhanced_link['client_secret'] = affiliate_link.get('rakuten_client_secret', affiliate_link.get('client_secret', ''))
                    enhanced_link['application_id'] = affiliate_link.get('rakuten_application_id', affiliate_link.get('application_id', ''))
                    
                elif platform == 'shareasale':
                    enhanced_link['shareasale_api_token'] = affiliate_link.get('api_token', '')
                    enhanced_link['shareasale_secret_key'] = affiliate_link.get('secret_key', '')
                    enhanced_link['affiliate_id'] = affiliate_link.get('affiliate_id', '')
                    
                elif platform == 'cj_affiliate':
                    enhanced_link['cj_api_key'] = affiliate_link.get('api_key', '')
                    enhanced_link['website_id'] = affiliate_link.get('website_id', '')
                    
                elif platform == 'skimlinks':
                    enhanced_link['skimlinks_api_key'] = affiliate_link.get('api_key', '')
                    enhanced_link['publisher_id'] = affiliate_link.get('publisher_id', '')
                
                logger.info(f"✅ Affiliate link retrieved: {platform} for {influencer_id}")
                return enhanced_link
            else:
                logger.info(f"📝 No affiliate link found: {platform} for {influencer_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting affiliate link by platform: {e}")
            return None

    def get_affiliate_links(self, influencer_id: str) -> List[Dict]:
        """FIXED: Get all affiliate links for an influencer with enhanced data"""
        try:
            response = self.supabase.table('affiliate_links') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .eq('is_active', True) \
                .execute()
            
            affiliate_links = response.data if response.data else []
            
            # Enhance each link with platform-specific data
            enhanced_links = []
            for link in affiliate_links:
                enhanced_link = dict(link)
                
                # Add platform display names
                platform_names = {
                    'amazon': 'Amazon Associates',
                    'rakuten': 'Rakuten Advertising', 
                    'shareasale': 'ShareASale',
                    'cj_affiliate': 'CJ Affiliate',
                    'skimlinks': 'Skimlinks'
                }
                
                enhanced_link['platform_name'] = platform_names.get(link['platform'], link['platform'].title())
                enhanced_links.append(enhanced_link)
            
            logger.info(f"✅ Retrieved {len(enhanced_links)} affiliate links for {influencer_id}")
            return enhanced_links
            
        except Exception as e:
            logger.error(f"Error getting affiliate links: {e}")
            return []

    def update_affiliate_link(self, influencer_id: str, platform: str, update_data: Dict) -> bool:
        """FIXED: Update an affiliate link"""
        try:
            # Add updated timestamp
            update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
            
            response = self.supabase.table('affiliate_links') \
                .update(update_data) \
                .eq('influencer_id', influencer_id) \
                .eq('platform', platform) \
                .execute()
            
            if response.data and len(response.data) > 0:
                logger.info(f"✅ Affiliate link updated: {platform} for {influencer_id}")
                return True
            else:
                logger.warning(f"⚠️ No affiliate link found to update: {platform} for {influencer_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating affiliate link: {e}")
            return False

    def delete_affiliate_link(self, influencer_id: str, platform: str) -> bool:
        """FIXED: Delete an affiliate link"""
        try:
            response = self.supabase.table('affiliate_links') \
                .delete() \
                .eq('influencer_id', influencer_id) \
                .eq('platform', platform) \
                .execute()
            
            if response.data and len(response.data) > 0:
                logger.info(f"✅ Affiliate link deleted: {platform} for {influencer_id}")
                return True
            else:
                logger.warning(f"⚠️ No affiliate link found to delete: {platform} for {influencer_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting affiliate link: {e}")
            return False

    def store_chat_interaction(self, interaction_data: Dict) -> bool:
        """FIXED: Store chat interaction for analytics with proper validation"""
        try:
            # Validate required fields
            required_fields = ['influencer_id', 'session_id', 'user_message', 'bot_response']
            for field in required_fields:
                if field not in interaction_data:
                    logger.warning(f"Missing field in chat interaction: {field}")
                    interaction_data[field] = interaction_data.get(field, '')
            
            # Add ID and timestamp if not present
            if 'id' not in interaction_data:
                interaction_data['id'] = str(uuid.uuid4())
            if 'created_at' not in interaction_data:
                interaction_data['created_at'] = datetime.now(timezone.utc).isoformat()
            
            # Ensure boolean fields are properly set
            interaction_data['has_video'] = bool(interaction_data.get('has_video', False))
            interaction_data['has_audio'] = bool(interaction_data.get('has_audio', False))
            interaction_data['knowledge_enhanced'] = bool(interaction_data.get('knowledge_enhanced', False))
            interaction_data['products_included'] = bool(interaction_data.get('products_included', False))
            
            response = self.supabase.table('chat_interactions').insert(interaction_data).execute()
            
            if response.data and len(response.data) > 0:
                logger.info(f"✅ Chat interaction stored: {interaction_data['session_id']}")
                return True
            else:
                logger.error(f"❌ Failed to store chat interaction")
                return False
                
        except Exception as e:
            logger.error(f"Error storing chat interaction: {e}")
            return False

    def get_knowledge_for_chat(self, influencer_id: str, query: str, limit: int = 3) -> Dict:
        """FIXED: Get comprehensive knowledge for chat responses"""
        try:
            result = {
                'personal_info': None,
                'relevant_chunks': [],
                'has_documents': False
            }
            
            # Get personal information
            personal_info = self.get_personal_knowledge(influencer_id)
            if personal_info:
                result['personal_info'] = personal_info
            
            # Check if user has uploaded documents
            documents = self.get_knowledge_documents(influencer_id)
            result['has_documents'] = len(documents) > 0
            
            # If we have documents, try to search them
            if result['has_documents']:
                try:
                    # This would require embedding generation which should be done by the RAG processor
                    # For now, we'll rely on the RAG processor integration in the chatbot
                    logger.info(f"📚 User has {len(documents)} documents available for knowledge search")
                except Exception as search_error:
                    logger.error(f"Knowledge search error: {search_error}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting knowledge for chat: {e}")
            return {'personal_info': None, 'relevant_chunks': [], 'has_documents': False}

    # =============================================================================
    # ADD THESE IMPORTS TO THE TOP OF YOUR DATABASE.PY FILE IF NOT PRESENT:
    # =============================================================================

    import logging
    logger = logging.getLogger(__name__)

    # =============================================================================
    # ENHANCED CHAT INTERACTION ANALYTICS
    # =============================================================================

    def get_chat_analytics(self, influencer_id: str, days: int = 30) -> Dict:
        """FIXED: Get comprehensive chat analytics"""
        try:
            from datetime import timedelta
            start_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            response = self.supabase.table('chat_interactions') \
                .select('*') \
                .eq('influencer_id', influencer_id) \
                .gte('created_at', start_date.isoformat()) \
                .execute()
            
            interactions = response.data if response.data else []
            
            # Calculate metrics
            total_chats = len(interactions)
            unique_sessions = len(set([chat.get("session_id") for chat in interactions if chat.get("session_id")]))
            knowledge_enhanced_chats = len([chat for chat in interactions if chat.get('knowledge_enhanced')])
            product_recommendation_chats = len([chat for chat in interactions if chat.get('products_included')])
            video_responses = len([chat for chat in interactions if chat.get('has_video')])
            audio_responses = len([chat for chat in interactions if chat.get('has_audio')])
            
            # Group by date for daily stats
            daily_stats = {}
            for interaction in interactions:
                date = interaction["created_at"][:10]  # YYYY-MM-DD
                if date not in daily_stats:
                    daily_stats[date] = {
                        'chats': 0,
                        'knowledge_enhanced': 0,
                        'products_included': 0,
                        'video_responses': 0,
                        'audio_responses': 0
                    }
                
                daily_stats[date]['chats'] += 1
                if interaction.get('knowledge_enhanced'):
                    daily_stats[date]['knowledge_enhanced'] += 1
                if interaction.get('products_included'):
                    daily_stats[date]['products_included'] += 1
                if interaction.get('has_video'):
                    daily_stats[date]['video_responses'] += 1
                if interaction.get('has_audio'):
                    daily_stats[date]['audio_responses'] += 1
            
            analytics_data = {
                "total_chats": total_chats,
                "unique_visitors": unique_sessions,
                "knowledge_enhanced_chats": knowledge_enhanced_chats,
                "product_recommendation_chats": product_recommendation_chats,
                "video_responses": video_responses,
                "audio_responses": audio_responses,
                "daily_stats": daily_stats,
                "avg_daily_chats": total_chats / days if days > 0 else 0,
                "knowledge_usage_rate": (knowledge_enhanced_chats / total_chats * 100) if total_chats > 0 else 0,
                "product_recommendation_rate": (product_recommendation_chats / total_chats * 100) if total_chats > 0 else 0,
                "period_days": days
            }
            
            logger.info(f"📊 Chat analytics calculated for {influencer_id}: {total_chats} chats, {unique_sessions} sessions")
            return analytics_data
            
        except Exception as e:
            logger.error(f"Error getting chat analytics: {e}")
            return {
                "total_chats": 0,
                "unique_visitors": 0,
                "knowledge_enhanced_chats": 0,
                "product_recommendation_chats": 0,
                "video_responses": 0,
                "audio_responses": 0,
                "daily_stats": {},
                "avg_daily_chats": 0,
                "knowledge_usage_rate": 0,
                "product_recommendation_rate": 0,
                "period_days": days
            }
