# deepscan/utils.py - NEW FILE

from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
import logging

logger = logging.getLogger(__name__)

def validate_auth_token(token_string):
    """
    Safely validate authentication token
    """
    try:
        if not token_string:
            return None
            
        # Try to get token from database
        token = Token.objects.select_related('user').get(key=token_string)
        return token.user
    except Token.DoesNotExist:
        logger.warning(f"Token not found: {token_string}")
        return None
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        return None

def get_user_from_request(request):
    """
    Safely get user from request with fallbacks
    """
    # Try authenticated user first
    if hasattr(request, 'user') and request.user.is_authenticated:
        return request.user
    
    # Try token authentication
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        user = validate_auth_token(token)
        if user:
            return user
    
    # Try session authentication
    if hasattr(request, 'session') and 'user_id' in request.session:
        User = get_user_model()
        try:
            return User.objects.get(id=request.session['user_id'])
        except User.DoesNotExist:
            pass
    
    return None