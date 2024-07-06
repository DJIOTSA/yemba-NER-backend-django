from rest_framework import serializers, validators
from django.contrib.auth import get_user_model

User = get_user_model()



class UserDetailSerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="user-detail", lookup_field='pk')
    class Meta:
        model = User
        fields = ["url", "pk", "username", "email", "first_name", "last_name"]

class SignupSerializer(serializers.ModelSerializer):
    """
    Don't require email to be unique so visitor can signup multiple times,
    if misplace verification email.  Handle in view.
    """
    class Meta:
        model = User
        fields = ('email', 'username', 'password', 'first_name', 'last_name')


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=128)

class PasswordResetSerializer(serializers.Serializer):
    new_password = serializers.CharField(max_length=255)


class PasswordResetVerifiedSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=40) 
    password = serializers.CharField(max_length=128)


class PasswordChangeSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=128)


class UserSerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="user-detail", lookup_field='pk')
    class Meta:
        model = User
        fields = '__all__'

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "email", 'password']

    