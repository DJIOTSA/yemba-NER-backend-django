from django.shortcuts import render, HttpResponse, redirect
from .serializers import (
    UserSerializer
)

from .models import (
    Status,
    SignupCode,
    PasswordResetCode,
    send_multi_format_email,
)

from .models import send_multi_format_email

from django.contrib.auth import get_user_model, authenticate, login, logout

User = get_user_model()
from datetime import date
from ipware import get_client_ip

from django.conf import settings

from django.utils.translation import gettext as _

from rest_framework import  authentication, permissions, generics
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import status
from rest_framework.authtoken.models import Token

from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


from django.core.exceptions import PermissionDenied

from user.serializers import (
    SignupSerializer, 
    LoginSerializer,
    PasswordResetSerializer,
    PasswordResetVerifiedSerializer,
    UserSerializer,
    UserProfileSerializer,

)
from django.views.generic import TemplateView
from django.urls import reverse
from django.http import HttpResponseRedirect



class SignupView(APIView):
    """ Sign Up USER."""
    authentication_classes = []
    permission_classes = (AllowAny,)
    serializer_class = SignupSerializer

    def post(self, request, format=None):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = serializer.data['email']
            password = serializer.data['password']
            username = serializer.data['username']
            first_name = serializer.data['first_name']
            last_name = serializer.data['last_name']
            
            must_validate_email = getattr(settings, "AUTH_EMAIL_VERIFICATION", True)

            try:
                user = get_user_model().objects.get(email=email)
                if user.is_verified:
                    content = {'detail': _('Email address already taken.')}
                    return Response(content, status=status.HTTP_400_BAD_REQUEST)

                try:
                    # Delete old signup codes
                    signup_code = SignupCode.objects.get(user=user)
                    signup_code.delete()
                except SignupCode.DoesNotExist:
                    pass

            except get_user_model().DoesNotExist:
                user = get_user_model().objects.create_user(email=email, username=username, status = Status.ACTIVE)

            # Set user fields provided
            user.set_password(password)
            # user.phone_number = phone_number
            user.first_name = first_name
            user.last_name = last_name
            
    
            if not must_validate_email:
                user.is_verified = True
                send_multi_format_email.delay('welcome_email',
                                        {'email': user.email, },
                                        target_email=user.email)
            user.save()

            if must_validate_email:
                # Create and associate signup code
                client_ip = get_client_ip(request)[0]
                if client_ip is None:
                    client_ip = '0.0.0.0'    # Unable to get the client's IP address
                signup_code = SignupCode.objects.create_signup_code(user, client_ip)
                signup_code.send_signup_email()

            content = {'email': email, 'first_name': first_name,
                       'last_name': last_name, 'username': username}
            return Response(content, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SignupVerify(APIView, TemplateView):
    authentication_classes = []
    permission_classes = (AllowAny,)
    template_name = 'erecommend/signup_verified.html'

    def get(self, request, format=None):
        code = request.GET.get('code', '')
        verified = SignupCode.objects.set_user_is_verified(code)

        if verified:
            try:
                signup_code = SignupCode.objects.get(code=code)
                signup_code.send_signup_verify('welcome_email')
                signup_code.delete()
                
            except SignupCode.DoesNotExist:
                pass

            content = {'detail': _('Email address verified.')}
            # return Response(content, status=status.HTTP_200_OK)
            return HttpResponseRedirect(reverse('signup-verified'), content)
            
        else:
            content = {'detail': _('Unable to verify user.')}
            # return Response(content, status=status.HTTP_400_BAD_REQUEST)
            return HttpResponseRedirect(reverse('signup-not-verified'), content)


class UserProfile(generics.ListAPIView):
    """ User Update first_name, last_name and country """
    authentication_classes = [authentication.TokenAuthentication, authentication.SessionAuthentication, JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    queryset = get_user_model().objects.all()
    serializer_class  = UserProfileSerializer
    lookup_key = "pk"

    def get_queryset(self):
        user = self.request.user
        queryset = self.queryset
        return queryset.filter(email=user.email)
    

class SignupVerifiedFrontEnd(TemplateView):
    template_name = 'erecommend/signup_verified.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['my_variable'] = 'my_value'
        return context


class SignupNotVerifiedFrontEnd(TemplateView):
    template_name = 'erecommend/signup_not_verified.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['my_variable'] = 'my_value'
        return context


class Login(APIView):
    """ Authenticated the user and assign user Authorizations """
    authentication_classes = []
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request, format=None):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = serializer.data['email']
            password = serializer.data['password']
            user = authenticate(email=email, password=password)

            if user:
                if user.is_verified:
                    if user.is_active:
                        login(request, user)
                        token, created = Token.objects.get_or_create(user=user)
                        return Response({'token': token.key},
                                        status=status.HTTP_200_OK)
                    else:
                        content = {'detail': _('User account not active.')}
                        return Response(content,
                                        status=status.HTTP_401_UNAUTHORIZED)
                else:
                    content = {'detail':
                               _('User account not verified.')}
                    return Response(content, status=status.HTTP_401_UNAUTHORIZED)
            else:
                content = {'detail':
                           _('Unable to login with provided credentials.')}
                return Response(content, status=status.HTTP_401_UNAUTHORIZED)

        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)


class Logout( APIView):
    queryset = User.objects.all()
    authentication_classes = [authentication.TokenAuthentication, authentication.SessionAuthentication, JWTAuthentication]
    permission_classes = (AllowAny, )

    def get(self, request, format=None):
        """
        Remove all auth tokens owned by request.user.
        """
        tokens = Token.objects.filter(user=request.user)
        for token in tokens:
            token.delete()
        logout(request)
        content = {'success': _('User logged out.')}
        return Response(content, status=status.HTTP_200_OK)


class PasswordReset( APIView,):
    """ 
    This view check if the user is active and then create a passwordResetCode
    With the for that user that will be used to identify the user and to change his password with 
    the new one sent by the user
    """
    queryset = User.objects.all()
    authentication_classes = [authentication.TokenAuthentication, authentication.SessionAuthentication, JWTAuthentication]
    permission_classes = (IsAuthenticated, )
    serializer_class = PasswordResetSerializer

    def post(self, request, format=None):
        """Sends a password reset email to the user specified in the request."""

        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = serializer.data['email']
            new_password = serializer.data['new_password']

            try:
                user = get_user_model().objects.get(email=email.lower())

                # Delete all unused password reset codes
                PasswordResetCode.objects.filter(user=user).delete()

                if user.is_verified and user.is_active:
                    password_reset_code = \
                        PasswordResetCode.objects.create_password_reset_code(user=user, new_password=new_password)
                    password_reset_code.send_password_reset_email()
                    content = {'email': email}
                    return Response(content, status=status.HTTP_201_CREATED)

            except get_user_model().DoesNotExist:
                content = {'detail': _('User with email address "{email}" does not exist.').format(email=email)}
                return Response(content, status=status.HTTP_404_NOT_FOUND)

            # Since this is AllowAny, don't give away error.
            content = {'detail': _('Password reset not allowed.')}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)

        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)


class PasswordResetVerify(APIView, TemplateView):
    authentication_classes = []
    queryset = User.objects.all()
    permission_classes = (AllowAny,)

    def get(self, request, format=None):
        code = request.GET.get('code', '')

        try:
            password_reset_code = PasswordResetCode.objects.get(code=code)

            # Delete password reset code if older than expiry period
            delta = date.today() - password_reset_code.created_at.date()
            if delta.days > PasswordResetCode.objects.get_expiry_period():
                password_reset_code.delete()
                raise PasswordResetCode.DoesNotExist()
            
            if password_reset_code.set_user_is_verified(code):
                password_reset_code.change_user_password()
                password_reset_code.delete()

            content = {'success': _('Email address verified.')}
            # return Response(content, status=status.HTTP_200_OK)
            return HttpResponseRedirect(reverse('password-reset-verified'))
        except PasswordResetCode.DoesNotExist:
            content = {'detail': _('Unable to verify user.')}
            # return Response(content, status=status.HTTP_400_BAD_REQUEST)
            return HttpResponseRedirect(reverse('password-reset-not-verified'))


class PasswordResetVerified(APIView):
    authentication_classes = []
    permission_classes = (AllowAny,)
    serializer_class = PasswordResetVerifiedSerializer

    def post(self, request, format=None):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            code = serializer.data['code']
            password = serializer.data['password']

            try:
                password_reset_code = PasswordResetCode.objects.get(code=code)
                password_reset_code.user.set_password(password)
                password_reset_code.user.save()

                # Delete password reset code just used
                password_reset_code.delete()

                content = {'success': _('Password reset.')}
                # return Response(content, status=status.HTTP_200_OK)
                return HttpResponseRedirect(reverse('password-reset-verified'))
            except PasswordResetCode.DoesNotExist:
                content = {'detail': _('Unable to verify user.')}
                # return Response(content, status=status.HTTP_400_BAD_REQUEST)
                return HttpResponseRedirect(reverse('password-reset-not-verified'))

        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)


class PasswordResetVerifiedFrontEnd(TemplateView):
    template_name = 'erecommend/password_verified.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['my_variable'] = 'my_value'
        return context


class PasswordResetNotVerifiedFrontEnd(TemplateView):
    template_name = 'erecommend/password_not_verified.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['my_variable'] = 'my_value'
        return context


class UserMe(generics.ListAPIView):
    queryset = User.objects.all()
    authentication_classes = [authentication.TokenAuthentication, authentication.SessionAuthentication, JWTAuthentication]
    permission_classes = (permissions.IsAdminUser, IsAuthenticated,)
    serializer_class = UserSerializer
    lookup_field = 'pk'


class UserDetail(generics.RetrieveAPIView):
    queryset = User.objects.all()
    authentication_classes = [authentication.TokenAuthentication, authentication.SessionAuthentication, JWTAuthentication]
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer
    lookup_field = 'pk'

    def get(self, request, *args, **kwargs):
        user = request.user
        object = self.get_object()

        if user != object:
            raise PermissionDenied
        
        return self.retrieve(request, *args, **kwargs)

