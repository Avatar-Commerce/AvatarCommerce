import os
from supabase import create_client, Client
from typing import Optional, Dict, List
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Database:
    def __init__(self):
        """Initialize Supabase client and ensure tables exist"""
        self.supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
 
    # Authentication methods
    def create_influencer(self, influencer_data: Dict) -> Optional[Dict]:
        """Create a new influencer with authentication credentials"""
        required_fields = {'id', 'username', 'email', 'password_hash'}
        if not all(field in influencer_data for field in required_fields):
            logger.error(f"Missing required fields: {required_fields}")
            return None

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

    # Profile management methods
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
        """Store original avatar file in Supabase Storage"""
        try:
            bucket_name = "influencer_assets"
            file_path = f"original_avatars/{influencer_id}/{file_name}"
            
            self.supabase.storage.from_(bucket_name).upload(file_path, file_bytes)
            self.update_influencer(influencer_id, {'original_asset_path': file_path})
            
            return file_path
        except Exception as e:
            logger.error(f"Error storing original asset: {str(e)}")
            return None

    def get_original_asset(self, influencer_id: str) -> Optional[bytes]:
        """Retrieve original avatar file"""
        try:
            influencer = self.get_influencer(influencer_id)
            if not influencer or not influencer.get('original_asset_path'):
                return None
                
            bucket_name = "influencer_assets"
            file_path = influencer['original_asset_path']
            
            return self.supabase.storage.from_(bucket_name).download(file_path)
        except Exception as e:
            logger.error(f"Error retrieving original asset: {str(e)}")
            return None