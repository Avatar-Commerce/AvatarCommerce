import os
import re
import logging
from typing import List, Dict, Optional
from datetime import datetime, timezone

import openai
import tiktoken
from supabase import create_client

# Document processing libraries
try:
    import PyPDF2
    from docx import Document as DocxDocument
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("⚠️ Install PyPDF2 and python-docx for document processing: pip install PyPDF2 python-docx")

logger = logging.getLogger(__name__)

class RAGProcessor:
    """
    RAG (Retrieval Augmented Generation) processor for knowledge documents
    Handles text extraction, chunking, embedding creation, and storage
    """
    
    def __init__(self, supabase_url: str, supabase_key: str, openai_api_key: str):
        self.supabase = create_client(supabase_url, supabase_key)
        self.openai_client = openai.OpenAI(api_key=openai_api_key)
        self.encoding = tiktoken.encoding_for_model("text-embedding-3-small")
                
    def process_document(self, document_id: str) -> bool:
        """
        Process a single document: extract text, create chunks, generate embeddings
        """
        try:
            # Get document from database
            response = self.supabase.table('knowledge_documents') \
                .select('*') \
                .eq('id', document_id) \
                .eq('is_processed', False) \
                .execute()
            
            if not response.data:
                logger.warning(f"Document {document_id} not found or already processed")
                return False
            
            document = response.data[0]
            
            # Download document from storage
            file_content = self._download_document(document['safe_filename'])
            if not file_content:
                return False
            
            # Extract text based on file type
            text_content = self._extract_text(file_content, document['content_type'])
            if not text_content:
                logger.error(f"Failed to extract text from {document['filename']}")
                return False
            
            # Create text chunks
            chunks = self._create_chunks(text_content)
            
            # Generate embeddings for chunks
            embeddings = self._generate_embeddings(chunks)
            
            # Store chunks and embeddings
            success = self._store_chunks_and_embeddings(
                document_id, 
                document['influencer_id'],  # This is now TEXT type
                chunks, 
                embeddings
            )
            
            if success:
                # Mark document as processed
                self.supabase.table('knowledge_documents') \
                    .update({
                        'is_processed': True,
                        'processed_date': datetime.now(timezone.utc).isoformat(),
                        'text_content': text_content[:5000],  # Store first 5000 chars for preview
                        'chunk_count': len(chunks)
                    }) \
                    .eq('id', document_id) \
                    .execute()
                
                logger.info(f"✅ Successfully processed document {document['filename']}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error processing document {document_id}: {e}")
            return False
    
    def _download_document(self, filename: str) -> Optional[bytes]:
        """Download document from Supabase storage"""
        try:
            bucket_name = "knowledge-documents"
            response = self.supabase.storage.from_(bucket_name).download(filename)
            return response
        except Exception as e:
            logger.error(f"Error downloading document {filename}: {e}")
            return None
    
    def _extract_text(self, file_content: bytes, content_type: str) -> Optional[str]:
        """Extract text from PDF or Word documents"""
        if not PDF_AVAILABLE:
            logger.error("Document processing libraries not available")
            return None
        
        try:
            if content_type == 'application/pdf':
                return self._extract_pdf_text(file_content)
            elif content_type in ['application/msword', 
                                 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                return self._extract_docx_text(file_content)
            else:
                logger.error(f"Unsupported content type: {content_type}")
                return None
        except Exception as e:
            logger.error(f"Error extracting text: {e}")
            return None
    
    def _extract_pdf_text(self, file_content: bytes) -> str:
        """Extract text from PDF using PyPDF2"""
        import io
        
        text = ""
        pdf_file = io.BytesIO(file_content)
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        
        return text.strip()
    
    def _extract_docx_text(self, file_content: bytes) -> str:
        """Extract text from Word document using python-docx"""
        import io
        
        doc_file = io.BytesIO(file_content)
        doc = DocxDocument(doc_file)
        
        text = ""
        for paragraph in doc.paragraphs:
            text += paragraph.text + "\n"
        
        return text.strip()
    
    def _create_chunks(self, text: str, max_tokens: int = 500, overlap: int = 50) -> List[str]:
        """
        Split text into chunks with overlap for better context preservation
        """
        # Clean and normalize text
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Split into sentences
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]
        
        chunks = []
        current_chunk = ""
        current_tokens = 0
        
        for sentence in sentences:
            sentence_tokens = len(self.encoding.encode(sentence))
            
            # If adding this sentence would exceed max_tokens, save current chunk
            if current_tokens + sentence_tokens > max_tokens and current_chunk:
                chunks.append(current_chunk.strip())
                
                # Start new chunk with overlap
                overlap_sentences = current_chunk.split('.')[-overlap:] if overlap > 0 else []
                current_chunk = '. '.join(overlap_sentences).strip()
                if current_chunk:
                    current_chunk += '. '
                current_tokens = len(self.encoding.encode(current_chunk))
            
            current_chunk += sentence + ". "
            current_tokens += sentence_tokens
        
        # Add final chunk
        if current_chunk.strip():
            chunks.append(current_chunk.strip())
        
        return chunks
    
    def _generate_embeddings(self, chunks: List[str]) -> List[List[float]]:
        """Generate embeddings for text chunks using OpenAI"""
        try:
            # Use OpenAI's text-embedding-3-small model (cheaper and faster)
            embeddings = []
            
            for chunk in chunks:
                response = self.openai_client.embeddings.create(
                    model="text-embedding-3-small",
                    input=chunk
                )
                embeddings.append(response.data[0].embedding)
            
            return embeddings
            
        except Exception as e:
            logger.error(f"Error generating embeddings: {e}")
            return []
    
    def _store_chunks_and_embeddings(self, document_id: str, influencer_id: str, 
                                   chunks: List[str], embeddings: List[List[float]]) -> bool:
        """Store text chunks and embeddings in database"""
        try:
            # Prepare chunk data
            chunk_data = []
            for i, (chunk, embedding) in enumerate(zip(chunks, embeddings)):
                chunk_data.append({
                    'document_id': document_id,
                    'influencer_id': influencer_id,  # Now TEXT type
                    'chunk_index': i,
                    'chunk_text': chunk,
                    'embedding': str(embedding),  # Store as string
                    'token_count': len(self.encoding.encode(chunk)),
                    'created_at': datetime.now(timezone.utc).isoformat()
                })
            
            # Store in chunks table
            response = self.supabase.table('knowledge_chunks').insert(chunk_data).execute()
            
            return bool(response.data)
            
        except Exception as e:
            logger.error(f"Error storing chunks and embeddings: {e}")
            return False
    
    def query_knowledge(self, influencer_id: str, query: str, top_k: int = 5) -> List[Dict]:
        """
        Query the knowledge base using semantic search
        """
        try:
            # Generate embedding for query
            response = self.openai_client.embeddings.create(
                model="text-embedding-3-small",
                input=query
            )
            query_embedding = response.data[0].embedding
            
            # Search for similar chunks using cosine similarity
            # Note: This is a simplified version. For production, use a proper vector database
            # like Pinecone, Weaviate, or pgvector extension for PostgreSQL
            
            response = self.supabase.table('knowledge_chunks') \
                .select('*, knowledge_documents(filename)') \
                .eq('influencer_id', influencer_id) \
                .execute()
            
            chunks = response.data if response.data else []
            
            # Calculate similarity scores (simplified cosine similarity)
            scored_chunks = []
            for chunk in chunks:
                if chunk['embedding']:
                    try:
                        # Parse embedding from string
                        chunk_embedding = eval(chunk['embedding'])  # Convert string back to list
                        similarity = self._cosine_similarity(query_embedding, chunk_embedding)
                        scored_chunks.append({
                            'chunk_text': chunk['chunk_text'],
                            'similarity': similarity,
                            'filename': chunk['knowledge_documents']['filename'] if chunk['knowledge_documents'] else 'Unknown',
                            'chunk_index': chunk['chunk_index']
                        })
                    except Exception as e:
                        logger.error(f"Error processing chunk embedding: {e}")
                        continue
            
            # Sort by similarity and return top_k
            scored_chunks.sort(key=lambda x: x['similarity'], reverse=True)
            return scored_chunks[:top_k]
            
        except Exception as e:
            logger.error(f"Error querying knowledge: {e}")
            return []
    
    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Calculate cosine similarity between two vectors"""
        import math
        
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        magnitude1 = math.sqrt(sum(a * a for a in vec1))
        magnitude2 = math.sqrt(sum(a * a for a in vec2))
        
        if magnitude1 == 0 or magnitude2 == 0:
            return 0
        
        return dot_product / (magnitude1 * magnitude2)
    
    def search_knowledge(self, query: str, influencer_id: str, limit: int = 3) -> List[Dict]:
        try:
            # Generate query embedding
            query_embedding = self.embedding_model.encode(query).tolist()
            
            # Search knowledge_chunks table
            response = self.supabase.table('knowledge_chunks') \
                .select('content, metadata') \
                .eq('influencer_id', influencer_id) \
                .execute()
            
            chunks = response.data if response.data else []
            if not chunks:
                return []
            
            # Calculate cosine similarity
            results = []
            for chunk in chunks:
                chunk_embedding = chunk.get('metadata', {}).get('embedding', [])
                if chunk_embedding:
                    similarity = np.dot(query_embedding, chunk_embedding) / (
                        np.linalg.norm(query_embedding) * np.linalg.norm(chunk_embedding)
                    )
                    results.append({
                        'content': chunk['content'],
                        'similarity': similarity
                    })
            
            # Sort by similarity and limit
            results = sorted(results, key=lambda x: x['similarity'], reverse=True)[:limit]
            return results
        
        except Exception as e:
            logger.error(f"RAG search error: {e}")
            return []