""" 
Django settings for ner project.

Generated by 'django-admin startproject' using Django 5.0.6.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

import dj_database_url
from pathlib import Path
import os, environ

env = environ.Env()
environ.Env.read_env()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ["*"]


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # third party apps
    'rest_framework',
    'rest_framework.authtoken',
    'rest_framework_simplejwt',
     "corsheaders",

    # our apps
    "user",
    "app",
]


REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],


    "DEFAULT_PERMISSION_CLASSES": [
        'rest_framework.permissions.IsAuthenticatedOrReadOnly',
    ],


    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 1000
}

from datetime import timedelta

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=12),
    "REFRESH_TOKEN_LIFETIME": timedelta(weeks=2),
    
    "AUTH_HEADER_TYPES": ("Bearer",),
}


MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

CORS_ALLOWED_ORIGINS = [
    "https://yembanerui.onrender.com",
    "https://yembanerui-c7e8-n2x1.onrender.com",
    "https://mhulo-yembaner.hf.space",
]

CORS_URLS_REGEX = r"^.*$"


ROOT_URLCONF = "ner.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, 'user/templates')],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "ner.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

# render PostgreSQL database live

DATABASES = {
    'default': dj_database_url.parse(env('DATABASE_URL')),
}


# default SQLite3 database
# DATABASES = {
#     "default": {
#         "ENGINE": "django.db.backends.sqlite3",
#         "NAME": BASE_DIR / "db.sqlite3",
#     }
# }


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_USER_MODEL = 'user.User'

EMAIL_FROM = os.environ.get('AUTHEMAIL_DEFAULT_EMAIL_FROM') or 'Yemba NER'
EMAIL_BCC = os.environ.get('AUTHEMAIL_DEFAULT_EMAIL_BCC') or 'Yemba NER'
EMAIL_HOST = os.environ.get('AUTHEMAIL_EMAIL_HOST') or 'smtp.gmail.com'
EMAIL_PORT = os.environ.get('AUTHEMAIL_EMAIL_PORT') or 587
"""
EMAIL_HOST_USER ='yembaner@gmail.com'
EMAIL_HOST_PASSWORD = 'sqkx aczl jyuj avwh'
"""
EMAIL_HOST_USER = os.environ.get(
    'AUTHEMAIL_EMAIL_HOST_USER') or 'yembaner@gmail.com'
EMAIL_HOST_PASSWORD = os.environ.get(
    'AUTHEMAIL_EMAIL_HOST_PASSWORD') or 'sqkx aczl jyuj avwh'
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False
# configure media file; update file trough the application
MEDIA_ROOT = os.path.join(BASE_DIR, 'media/')
MEDIA_URL = 'media/'
