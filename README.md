# AvatarCommerce

AvatarCommerce is a platform that enables influencers to create AI-powered avatars that can engage with their audience and provide personalized product recommendations through an affiliate marketing model.

## Overview

This API-first platform connects influencers with their audiences through AI-powered digital avatars. Followers can chat with an influencer's avatar, which provides personalized product recommendations with embedded affiliate links, creating a passive income stream for content creators.

## Features

- **Personalized Avatars**: Create AI avatars from uploaded photos using HeyGen API integration
- **Conversational AI**: Chat with followers using LLM-based responses
- **Product Recommendations**: Automatically detect product intent and provide relevant recommendations
- **Affiliate Integration**: Built-in affiliate link tracking for multiple platforms
- **Video Responses**: Generate video responses featuring the influencer's avatar
- **Analytics Dashboard**: Track interactions and conversion metrics

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new influencer account
- `POST /api/auth/login` - Login and get JWT token

### Avatar Management
- `POST /api/avatar/create` - Create a HeyGen avatar from uploaded media

### Affiliate Management
- `POST /api/affiliate` - Add or update affiliate information
- `GET /api/affiliate` - Get all affiliate links for the current user

### Chat Functionality
- `POST /api/chat` - Send a message to the chatbot and get a response with video
- `GET /api/chat/<username>` - Get public chat page info for an influencer

### Analytics
- `GET /api/analytics/dashboard` - Get dashboard data for the influencer

## Technology Stack

- **Backend**: Python, Flask
- **Database**: PostgreSQL (via Supabase)
- **Storage**: Supabase Storage
- **AI Services**: 
  - OpenAI API for conversational AI
  - HeyGen API for avatar creation and video generation
  - Apify for product recommendations

## Environment Setup

1. Clone the repository
   ```
   git clone https://github.com/yourusername/avatarcommerce.git
   cd avatarcommerce
   ```

2. Create a virtual environment
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies
   ```
   pip install -r requirements.txt
   ```

4. Create a `.env` file with required credentials
   ```
   SUPABASE_URL=your_supabase_url
   SUPABASE_KEY=your_supabase_key
   SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key
   OPENAI_API_KEY=your_openai_api_key
   HEYGEN_API_KEY=your_heygen_api_key
   APIFY_API_KEY=your_apify_api_key
   JWT_SECRET_KEY=your_jwt_secret_key
   ```

5. Start the server
   ```
   python main.py
   ```

## Testing with Postman

A complete Postman collection is available for testing all API endpoints. Import the collection and environment files provided in the `postman` directory to get started quickly.

1. Register a new influencer account
2. Login to get a JWT token
3. Create an avatar using an image upload
4. Add affiliate information
5. Test the chat functionality
6. View analytics data

## Development

### Database Schema

The application uses three main tables:
- `influencers`: Stores user accounts and avatar information
- `affiliate_links`: Tracks affiliate program connections
- `chat_interactions`: Logs all user conversations and recommendations

### Extending the Platform

To add new features or integrations:
1. Extend the appropriate class in the codebase
2. Update the API documentation with Swagger
3. Add new environment variables if needed
4. Update tests to cover new functionality

## Deployment

The application can be deployed to any platform that supports Python applications:

1. Set up all required environment variables
2. Ensure the database and storage are properly configured
3. Run the application with a production WSGI server like Gunicorn:
   ```
   gunicorn -w 4 -b 0.0.0.0:8081 main:app
   ```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- HeyGen for their avatar generation technology
- OpenAI for conversational AI capabilities
- Supabase for database and storage solutions
- Apify for product recommendation scraping tools