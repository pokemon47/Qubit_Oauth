from flask import Flask, request, jsonify
from flask_cors import CORS
from google.oauth2 import id_token
from google.auth.transport import requests
import os
from dotenv import load_dotenv
import requests as http_requests
import jwt
from datetime import datetime, timedelta

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key-here')  # Change in production

@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    try:
        data = request.get_json()
        code = data.get('code')
        code_verifier = data.get('code_verifier')

        # Exchange code for token
        token_url = 'https://oauth2.googleapis.com/token'
        token_data = {
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code_verifier': code_verifier,
            'grant_type': 'authorization_code',
            'redirect_uri': f"{request.headers.get('Origin')}/auth/callback"
        }

        token_response = http_requests.post(token_url, data=token_data)
        if not token_response.ok:
            return jsonify({'error': 'Failed to exchange code'}), 400

        token_json = token_response.json()
        id_token_jwt = token_json['id_token']

        # Verify the token
        idinfo = id_token.verify_oauth2_token(
            id_token_jwt, requests.Request(), GOOGLE_CLIENT_ID)

        # Create user session token
        session_token = jwt.encode({
            'sub': idinfo['sub'],
            'email': idinfo['email'],
            'name': idinfo.get('name'),
            'picture': idinfo.get('picture'),
            'exp': datetime.utcnow() + timedelta(days=1)
        }, JWT_SECRET_KEY, algorithm='HS256')

        response = jsonify({
            'email': idinfo['email'],
            'name': idinfo.get('name'),
            'picture': idinfo.get('picture')
        })
        
        # Set session cookie
        response.set_cookie(
            'session_token',
            session_token,
            httponly=True,
            secure=True,
            samesite='Lax',
            max_age=86400  # 24 hours
        )

        return response

    except Exception as e:
        print(f"Error in /auth/google: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 401

@app.route('/api/auth/verify', methods=['GET'])
def verify_session():
    try:
        session_token = request.cookies.get('session_token')
        if not session_token:
            return jsonify({'error': 'No session'}), 401

        # Verify the session token
        payload = jwt.decode(session_token, JWT_SECRET_KEY, algorithms=['HS256'])
        
        return jsonify({
            'email': payload['email'],
            'name': payload['name'],
            'picture': payload['picture']
        })

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Session expired'}), 401
    except Exception as e:
        print(f"Error in /auth/verify: {str(e)}")
        return jsonify({'error': 'Invalid session'}), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    response = jsonify({'message': 'Logged out successfully'})
    response.delete_cookie('session_token')
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))