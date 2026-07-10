from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import RegisterView, LoginView, ProfileView, LogoutView, ValidateClientView,GenerateClientTokenView, ValidateClientTokenView


urlpatterns = [
    path('auth/register/', RegisterView.as_view(), name='auth-register'),
    path('auth/login/', LoginView.as_view(), name='auth-login'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='auth-refresh'),
    path('auth/profile/', ProfileView.as_view(), name='auth-profile'),
    path('auth/logout/', LogoutView.as_view(), name='auth-logout'),
    path('auth/validate-client/', ValidateClientView.as_view(), name='auth-validate-client'),
     path('clients/generate-token/', GenerateClientTokenView.as_view(), name='generate-client-token'),
    path('clients/validate-token/', ValidateClientTokenView.as_view(), name='validate-client-token'),
]

