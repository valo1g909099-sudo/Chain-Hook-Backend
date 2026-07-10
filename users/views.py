import base64
import json
from urllib.parse import urlencode

from django.utils import timezone
from rest_framework import status, generics, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.core import signing
from .models import User, Client, UserActivityLog
from .serializers import UserSerializer, UserCreateSerializer
from .serializers import GenerateClientTokenSerializer 
from django.core.signing import BadSignature, SignatureExpired


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def issue_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'access': str(refresh.access_token),
        'refresh': str(refresh),
    }


def build_client_redirect(base_url, **params):
    if not base_url:
        return None
    separator = '&' if '?' in base_url else '?'
    return f"{base_url}{separator}{urlencode(params)}"


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserCreateSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        tokens = issue_tokens_for_user(user)

        UserActivityLog.objects.create(
            user=user,
            action='create',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'source': 'register'}
        )

        return Response(
            {
                'user': UserSerializer(user).data,
                'tokens': tokens,
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email', '').strip().lower()
        password = request.data.get('password')
        client_id = request.data.get('client_id')

        if not email or not password:
            return Response(
                {'detail': 'Email and password are required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            user = None

        if user is None or not user.check_password(password):
            return Response(
                {'detail': 'Invalid email or password.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.is_active:
            return Response(
                {'detail': 'This account has been deactivated.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        client = None
        redirect_url = None
        if client_id:
            try:
                client = Client.objects.get(pk=int(client_id), is_active=True)
                base_url = None
                if client.for_login:
                    base_url = client.get_login_url()
                elif client.for_payment:
                    base_url = client.get_payment_url()
                redirect_url = build_client_redirect(
                    base_url,
                    status='success',
                    email=email,
                )
            except (Client.DoesNotExist, ValueError, TypeError):
                try:
                    padded_client_id = str(client_id)
                    padded_client_id += '=' * (-len(padded_client_id) % 4)
                    decoded_bytes = base64.b64decode(padded_client_id)
                    decoded_str = decoded_bytes.decode('utf-8')
                    client_info = json.loads(decoded_str)

                    p_name = (client_info.get('platform_name') or client_info.get('merchant_name') or '').strip()
                    p_url = (client_info.get('platform_url') or '').strip()
                    flow_type = (client_info.get('type') or '').strip()

                    if not p_name or not p_url:
                        return Response(
                            {'detail': 'Decoded client payload missing name or url.'},
                            status=status.HTTP_400_BAD_REQUEST,
                        )

                    normalized_url = p_url.rstrip('/')
                    candidates = Client.objects.filter(name__iexact=p_name, is_active=True)
                    db_client = None
                    for candidate in candidates:
                        if candidate.base_url.rstrip('/') == normalized_url:
                            db_client = candidate
                            break

                    if not db_client:
                        return Response(
                            {'detail': f"No registered client matching name '{p_name}' and URL '{p_url}' was found."},
                            status=status.HTTP_400_BAD_REQUEST,
                        )

                    if flow_type == 'login' and not db_client.for_login:
                        return Response(
                            {'detail': f"Client '{p_name}' is not authorized for login flows."},
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                    if flow_type == 'payment' and not db_client.for_payment:
                        return Response(
                            {'detail': f"Client '{p_name}' is not authorized for payment flows."},
                            status=status.HTTP_400_BAD_REQUEST,
                        )

                    client = db_client

                    base_url = None
                    if flow_type == 'login':
                        base_url = client.get_login_url()
                    elif flow_type == 'payment':
                        base_url = client.get_payment_url()

                    redirect_url = build_client_redirect(
                        base_url,
                        status='success',
                        email=email,
                    )
                except Exception:
                    return Response(
                        {'detail': 'Unknown or inactive client application.'},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

        tokens = issue_tokens_for_user(user)

        UserActivityLog.objects.create(
            user=user,
            action='login',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'client_id': str(client.id) if client else None},
        )

        return Response(
            {
                'user': UserSerializer(user).data,
                'tokens': tokens,
                'client': {
                    'id': client.id,
                    'name': client.name,
                    'redirect_url': redirect_url,
                } if client else None,
            },
            status=status.HTTP_200_OK,
        )


class ValidateClientView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        client_id = request.query_params.get('client_id', '').strip()

        if not client_id:
            return Response(
                {
                    'valid': False,
                    'reason': 'missing_client_id',
                    'message': 'No client_id was provided in the request.',
                    'details': {}
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            padded = client_id + '=' * (-len(client_id) % 4)
            decoded_bytes = base64.b64decode(padded)
            decoded_str = decoded_bytes.decode('utf-8')
            payload = json.loads(decoded_str)
            if not isinstance(payload, dict):
                raise ValueError('Payload is not a JSON object.')
        except Exception as exc:
            return Response(
                {
                    'valid': False,
                    'reason': 'decode_error',
                    'message': 'The client_id could not be decoded. It must be a valid Base64-encoded JSON object.',
                    'details': {'error': str(exc)}
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        platform_name = (payload.get('platform_name') or payload.get('merchant_name') or '').strip()
        platform_url  = (payload.get('platform_url') or '').strip()
        flow_type     = (payload.get('type') or '').strip()

        missing_fields = []
        if not platform_name:
            missing_fields.append('platform_name')
        if not platform_url:
            missing_fields.append('platform_url')
        if not flow_type:
            missing_fields.append('type')

        if missing_fields:
            return Response(
                {
                    'valid': False,
                    'reason': 'missing_payload_fields',
                    'message': f'The decoded payload is missing required fields: {missing_fields}',
                    'details': {
                        'missing_fields': missing_fields,
                        'received_payload': payload,
                    }
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if flow_type not in ('login', 'payment'):
            return Response(
                {
                    'valid': False,
                    'reason': 'invalid_type',
                    'message': f"Flow type must be 'login' or 'payment'. Got: '{flow_type}'.",
                    'details': {'received_type': flow_type}
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        name_matches = Client.objects.filter(name__iexact=platform_name, is_active=True)

        if not name_matches.exists():
            return Response(
                {
                    'valid': False,
                    'reason': 'client_name_not_found',
                    'message': f"No registered client found with the name '{platform_name}'.",
                    'details': {
                        'platform_name': platform_name,
                        'platform_url':  platform_url,
                    }
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        normalized_url = platform_url.rstrip('/')
        url_match = None
        for candidate in name_matches:
            if candidate.base_url.rstrip('/') == normalized_url:
                url_match = candidate
                break

        if url_match is None:
            registered_urls = [c.base_url for c in name_matches]
            return Response(
                {
                    'valid': False,
                    'reason': 'base_url_mismatch',
                    'message': (
                        f"A client named '{platform_name}' was found, but the platform_url "
                        f"'{platform_url}' does not match its registered base URL."
                    ),
                    'details': {
                        'platform_name':   platform_name,
                        'provided_url':    platform_url,
                        'registered_urls': registered_urls,
                    }
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        if flow_type == 'login' and not url_match.for_login:
            return Response(
                {
                    'valid': False,
                    'reason': 'flow_not_permitted',
                    'message': f"Client '{platform_name}' is not authorized for 'login' flows.",
                    'details': {
                        'platform_name': platform_name,
                        'for_login':     url_match.for_login,
                        'for_payment':   url_match.for_payment,
                    }
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        if flow_type == 'payment' and not url_match.for_payment:
            return Response(
                {
                    'valid': False,
                    'reason': 'flow_not_permitted',
                    'message': f"Client '{platform_name}' is not authorized for 'payment' flows.",
                    'details': {
                        'platform_name': platform_name,
                        'for_login':     url_match.for_login,
                        'for_payment':   url_match.for_payment,
                    }
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        return Response(
            {
                'valid': True,
                'reason': 'ok',
                'message': 'Client validated successfully.',
                'client': {
                    'id':          url_match.id,
                    'name':        url_match.name,
                    'base_url':    url_match.base_url,
                    'for_login':   url_match.for_login,
                    'for_payment': url_match.for_payment,
                },
                'payload': payload,
            },
            status=status.HTTP_200_OK,
        )


class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return Response(UserSerializer(request.user).data)

    def patch(self, request, *args, **kwargs):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            
            UserActivityLog.objects.create(
                user=user,
                action='update',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details={'updated_fields': list(request.data.keys())}
            )
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response(
                {'detail': 'Refresh token is required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception:
            return Response(
                {'detail': 'Invalid or expired refresh token.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        UserActivityLog.objects.create(
            user=request.user,
            action='logout',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )

        return Response(status=status.HTTP_205_RESET_CONTENT)
    


CLIENT_TOKEN_SALT = 'oauth-client-id-v1'
CLIENT_TOKEN_MAX_AGE = 60 * 10 


def decode_client_token(client_id: str):
    
    try:
        payload = signing.loads(client_id, salt=CLIENT_TOKEN_SALT, max_age=CLIENT_TOKEN_MAX_AGE)
    except SignatureExpired:
        raise ValueError('This authorization link has expired. Please generate a new one.')
    except BadSignature:
        raise ValueError('Invalid or tampered client token.')

    try:
        client = Client.objects.get(pk=payload['client_db_id'], is_active=True)
    except (Client.DoesNotExist, KeyError):
        raise ValueError('Client no longer exists or is inactive.')

    return payload, client


class GenerateClientTokenView(APIView):
   

    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = GenerateClientTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        api_key = data['api_key']
        platform_name = data['platform_name']
        base_url = data['base_url']
        flow_type = data['type']

        try:
            client = Client.objects.get(api_key=api_key, is_active=True)
        except Client.DoesNotExist:
            return Response(
                {'detail': 'Invalid API key.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if (client.name or '').strip().lower() != platform_name.strip().lower():
            return Response(
                {'detail': 'platform_name does not match the client registered for this API key.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        if client.base_url.rstrip('/') != base_url.rstrip('/'):
            return Response(
                {'detail': 'base_url does not match the client registered for this API key.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        if flow_type == 'login' and not client.for_login:
            return Response(
                {'detail': f"Client '{client.name}' is not authorized for login flows."},
                status=status.HTTP_403_FORBIDDEN,
            )
        if flow_type == 'payment' and not client.for_payment:
            return Response(
                {'detail': f"Client '{client.name}' is not authorized for payment flows."},
                status=status.HTTP_403_FORBIDDEN,
            )

        payload = {
            'client_db_id': client.id,
            'platform_name': client.name,
            'platform_url': client.base_url,
            'type': flow_type,
            'merchant_name': data['merchant_name'],
            'total_price': data.get('total_price') or None,
        }
        token = signing.dumps(payload, salt=CLIENT_TOKEN_SALT, compress=True)

        return Response({'client_id': token}, status=status.HTTP_200_OK)


class ValidateClientTokenView(APIView):
    """
    GET /api/clients/validate-token/?client_id=<token>

    Drop-in replacement for the old ValidateClientView. Instead of
    base64-decoding arbitrary JSON, it verifies the signature that only
    the server could have produced.
    """

    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        client_id = request.query_params.get('client_id', '').strip()

        if not client_id:
            return Response(
                {'valid': False, 'reason': 'missing_client_id',
                 'message': 'No client_id was provided in the request.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            payload, client = decode_client_token(client_id)
        except ValueError as exc:
            return Response(
                {'valid': False, 'reason': 'invalid_token', 'message': str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                'valid': True,
                'reason': 'ok',
                'message': 'Client token validated successfully.',
                'client': {
                    'id': client.id,
                    'name': client.name,
                    'base_url': client.base_url,
                    'for_login': client.for_login,
                    'for_payment': client.for_payment,
                },
                'payload': payload,
            },
            status=status.HTTP_200_OK,
        )
