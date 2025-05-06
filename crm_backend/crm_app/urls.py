from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from django.views.decorators.csrf import csrf_exempt
from .views import UserRegisterAPIView, LoginAPIView, SetPasswordAPIView, ForgotPasswordAPIView

urlpatterns = [
    path('register/', UserRegisterAPIView.as_view(), name='register'),
    path('login/', csrf_exempt(LoginAPIView.as_view()), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('set-password/<uuid:token>/', SetPasswordAPIView.as_view(), name='set-password'),
    path('forgot-password/', ForgotPasswordAPIView.as_view(), name='forgot-password'),
] 