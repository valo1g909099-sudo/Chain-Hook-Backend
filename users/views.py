from django.utils import timezone
from rest_framework import status, generics, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.core import signing
from django.core.signing import BadSignature, SignatureExpired

from .models import User, Client, UserActivityLog
from .serializers import UserSerializer, UserCreateSerializer
from .serializers import GenerateClientTokenSerializer


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
    from urllib.parse import urlencode
    separator = '&' if '?' in base_url else '?'
    return f"{base_url}{separator}{urlencode(params)}"


# ---------------------------------------------------------------------------
# Signed client_id tokens
#
# This is now the ONLY mechanism for client_id. There is no more base64(JSON)
# fallback anywhere in this file. A client_id is either a valid signed token
# (produced exclusively by GenerateClientTokenView) or it's rejected outright.
# ---------------------------------------------------------------------------

CLIENT_TOKEN_SALT = 'oauth-client-id-v1'
CLIENT_TOKEN_MAX_AGE = 60 * 10  # 10 minutes


def decode_client_token(client_id: str):
    """
    Verify and decode a signed client_id token.
    Raises ValueError with a user-facing message on any failure.
    """
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
    """
    POST /api/users/auth/login/

    `client_id`, if present, MUST be a signed token minted by
    GenerateClientTokenView. There is no other accepted format.
    """
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
                payload, client = decode_client_token(client_id)
            except ValueError as exc:
                return Response(
                    {'detail': str(exc)},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            flow_type = payload.get('type')
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


class GenerateClientTokenView(APIView):
    """
    POST /api/users/clients/generate-token/

    Server-side minting of a signed client_id. Requires a valid api_key
    that matches a registered, active Client, plus a platform_name/base_url
    that match that Client's record.
    """
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
    GET /api/users/clients/validate-token/?client_id=<token>

    The only client_id validation endpoint. Verifies the signature that
    only the server could have produced — no base64/JSON parsing of
    arbitrary client-supplied data.
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
