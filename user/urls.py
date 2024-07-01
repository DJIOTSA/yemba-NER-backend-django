from django.urls import path
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

urlpatterns = [
    path('users/', views.UserMe.as_view(), name="users-list"),
    path("<int:pk>/update/", views.UserUpdate.as_view(), name="user-update"),
    path("<int:pk>/", views.UserDetail.as_view(), name="user-detail"),    
    # user sign up
    path('signup/', views.SignupView.as_view(), name='signup-admin'),
    path('signup/verify/', views.SignupVerify.as_view(), name='signup-verify'),
    path('signup/not_verified/', views.SignupNotVerifiedFrontEnd.as_view(),name='signup-not-verified'),
    path('signup/verified/', views.SignupVerifiedFrontEnd.as_view(),name='signup-verified'),
    path('login/', views.Login.as_view(), name='login'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'), # jwt
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), # jwt
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'), # jwt

    path('logout/', views.Logout.as_view(), name='logout'),
    # password reset
    path('password/reset/', views.PasswordReset.as_view(), name='password-reset'),
    path('password/reset/verify/', views.PasswordResetVerify.as_view(), name='password-reset-verify'),
    path('password/reset/verified/', views.PasswordResetVerifiedFrontEnd.as_view(), name='password-reset-verified'),
    path('password/reset/not_verified/', views.PasswordResetNotVerifiedFrontEnd.as_view(), name='password-reset-not-verified'),
]
