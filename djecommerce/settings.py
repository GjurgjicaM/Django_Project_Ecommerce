"""
Django settings for djecommerce project.

Generated by 'django-admin startproject' using Django 5.0.7.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "django-insecure-2=7(^)hk061!m4rw@kt2+o1b_!@w)8suufufvi&4io+8qom1ga"

DEBUG = True

ALLOWED_HOSTS = []


INSTALLED_APPS = [
    "jazzmin",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "crispy_forms",
    'crispy_bootstrap4',
    'django.contrib.sites',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    "django_countries",
    "core",
    "crispy_tailwind"
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    'allauth.account.middleware.AccountMiddleware',
    
]

ROOT_URLCONF = "djecommerce.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "templates")],
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

WSGI_APPLICATION = "djecommerce.wsgi.application"


DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


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

SITE_ID = 2
LOGIN_URL = 'core:account_login'
LOGOUT_URL = 'core:custom_logout'
LOGIN_REDIRECT_URL = '/'

STRIPE_PUBLIC_KEY = 'pk_test_51Q5OhAHQu4NIJAfGTdncIRe8DXGyvDfh9hZZ6QyOiNl7AzT3ItDtV79GI3OY9m3EeU7nIthROP9felmBsE6MPmSp00lpldqWYY'
STRIPE_SECRET_KEY = 'sk_test_51Q5OhAHQu4NIJAfG78PGeoyabqce9vpdAqXTLZAhhk6oiNRWN6NN07Sc961kQ0c25LFiAxA9Q50fLkFNK2ZKxlTn000HKOCRrB'

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = "/static/"
STATICFILES_DIRS = [os.path.join(BASE_DIR, "static_in_env")]

CRISPY_ALLOWED_TEMPLATE_PACKS = ["tailwind"]
CRISPY_TEMPLATE_PACK = "tailwind"



# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")


# settings.py

JAZZMIN_SETTINGS = {
    # Title of the admin site
    "site_title": "My E-commerce Admin",

    # Title of the dashboard when no title is set (i.e. 'Django Admin')
    "site_header": "E-commerce Site",

    # Welcome text on the dashboard
    "welcome_sign": "Welcome to the E-commerce Admin!",

    # Copyright on the footer
    "copyright": "2025 E-commerce Site",

    # Links to include in the sidebar (optional)
    "sidebar_links": [
        {
            "name": "Home",
            "url": "admin:index",
            "icon": "fas fa-home",
            "new_window": False
        },
        {"model": "auth.User"},
        {"app": "core"}, # Link to your 'core' app models
        # Add more custom links or app/model links here
    ],

    # Flat theme for minimal styling (optional)
    "changeform_format": "horizontal_tabs", # or "vertical_tabs", "single_inline", "collapsible"
}

JAZZMIN_UI_TWEAKS = {
    "navbar_small_text": False,
    "footer_small_text": False,
    "body_small_text": False,
    "brand_small_text": False,
    "brand_colour": "navbar-dark", # or a specific color like "bg-purple-600"
    "accent": "accent-primary",
    "navbar": "navbar-white navbar-light",
    "no_navbar_border": False,
    "navbar_fixed": False,
    "layout_boxed": False,
    "footer_fixed": False,
    "sidebar_is_nav_small_text": False,
    "sidebar_disable_expand": False,
    "sidebar_nav_child_indent": True,
    "sidebar_nav_compact_style": False,
    "sidebar_nav_legacy_style": False,
    "sidebar_nav_flat_style": False,
    "theme": "flatly", # Choose a theme like 'flatly', 'cerulean', 'simplex', 'darkly', etc.
    "dark_mode_listener": False,
    "dark_mode_theme": "darkly",
}

EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True

EMAIL_HOST_USER = 'dnickecomerce@gmail.com'
EMAIL_HOST_PASSWORD = 'vyjbjsppqcygaalf'



