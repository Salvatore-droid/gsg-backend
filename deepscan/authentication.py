# deepscan/authentication.py - FIXED VERSION

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

class JWTAuthentication(authentication.BaseAuthentication):
    """
    JWT Authentication for GeniusGuard API
    """
    
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return None
            
        if not auth_header.startswith('Bearer '):
            return None
            
        token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id')
            
            if not user_id:
                raise AuthenticationFailed('Invalid token')
                
            user = User.objects.get(id=user_id)
            return (user, token)
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found')
        except Exception as e:
            logger.error(f"JWT authentication error: {str(e)}")
            raise AuthenticationFailed('Authentication failed')

class SessionOrJWTAuthentication(authentication.BaseAuthentication):
    """
    Combined authentication that tries Session first, then JWT
    """
    
    def authenticate(self, request):
        # First try session authentication - SAFE APPROACH
        # Access the underlying Django request user to avoid recursion
        user = getattr(request._request, 'user', None)
        
        if user and user.is_authenticated:
            return (user, None)
            
        # Then try JWT authentication
        jwt_auth = JWTAuthentication()
        try:
            return jwt_auth.authenticate(request)
        except AuthenticationFailed:
            return None
        except Exception:
            return None