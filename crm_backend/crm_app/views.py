from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from .serializers import UserSerializer, LoginSerializer, SetPasswordSerializer, ForgotPasswordSerializer
from .models import User, PasswordResetToken

class UserRegisterAPIView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        # Create password reset token
        token = PasswordResetToken.objects.create(
            user=user,
            expires_at=timezone.now() + timedelta(hours=1)
        )
        # Send email with password set link
        reset_url = f"{settings.FRONTEND_URL}/api/set-password/{token.token}/"
        send_mail(
            'Set Your Password',
            f'''Please click the following link to set your password: {reset_url}

Or you can use these curl commands to set your password:

1. Check token validity:
curl -X GET {reset_url}

2. Set password:
curl -X POST {reset_url} -H "Content-Type: application/json" -d '{{"password": "your_password", "password2": "your_password"}}'

Note: The link will expire in 1 hour.''',
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
        )

class LoginAPIView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(
            email=serializer.validated_data['email'],
            password=serializer.validated_data['password']
        )

        if user and user.has_set_password:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        else:
            return Response(
                {'error': 'Invalid credentials or password not set'},
                status=status.HTTP_401_UNAUTHORIZED
            )

class SetPasswordAPIView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = SetPasswordSerializer

    def get(self, request, token):
        try:
            token_obj = PasswordResetToken.objects.get(token=token)
            if not token_obj.is_valid():
                return Response(
                    {'error': 'Token is invalid or has expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            return Response({
                'email': token_obj.user.email,
                'message': 'Token is valid'
            })
        except PasswordResetToken.DoesNotExist:
            return Response(
                {'error': 'Invalid token'},
                status=status.HTTP_400_BAD_REQUEST
            )

    def post(self, request, token):
        try:
            token_obj = PasswordResetToken.objects.get(token=token)
            if not token_obj.is_valid():
                return Response(
                    {'error': 'Token is invalid or has expired'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            user = token_obj.user
            user.set_password(serializer.validated_data['password'])
            user.has_set_password = True
            user.save()

            token_obj.is_used = True
            token_obj.save()

            return Response({'message': 'Password set successfully'})
        except PasswordResetToken.DoesNotExist:
            return Response(
                {'error': 'Invalid token'},
                status=status.HTTP_400_BAD_REQUEST
            )

class ForgotPasswordAPIView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            # Create password reset token
            token = PasswordResetToken.objects.create(
                user=user,
                expires_at=timezone.now() + timedelta(hours=1)
            )
            # Send email with password reset link
            reset_url = f"{settings.FRONTEND_URL}/api/set-password/{token.token}/"
            send_mail(
                'Reset Your Password',
                f'''Please click the following link to reset your password: {reset_url}

Or you can use these curl commands to reset your password:

1. Check token validity:
curl -X GET {reset_url}

2. Set new password:
curl -X POST {reset_url} -H "Content-Type: application/json" -d '{{"password": "your_password", "password2": "your_password"}}'

Note: The link will expire in 1 hour.''',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            return Response({'message': 'Password reset link sent to your email'})
        except User.DoesNotExist:
            return Response(
                {'error': 'No user found with this email address'},
                status=status.HTTP_404_NOT_FOUND
            ) 