import json
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import Group
from django.contrib.auth.models import AbstractUser, AbstractBaseUser, BaseUserManager, PermissionsMixin
from users.avatar_colours import AvatarColours


class CustomUserManager(BaseUserManager):

    # ======= THESE METHODS USED WHEN CREATING USERS VIA COMMAND LINE (MANAGE.PY) =======#
    def create_user(self, email, password, first_name, last_name, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address")

        email = self.normalize_email(email)
        first_name = first_name.capitalize()
        last_name = last_name.capitalize()

        # Generate initials (e.g., John Smith -> JS)
        initials = (first_name[:1] + last_name[:1]).upper()
        bg, fg = AvatarColours.get_random_avatar_color()

        user = self.model(
            email=email,
            first_name=first_name,
            last_name=last_name,
            initials=initials,
            avatar={
                "fg_colour": fg,
                "bg_colour": bg,
                "filename": None,
            },
            ** extra_fields
        )
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, first_name, last_name, **extra_fields):
        extra_fields = {**extra_fields, "is_staff": True,
                        "is_superuser": True, "is_active": True}

        user = self.create_user(email=email, password=password,
                                first_name=first_name, last_name=last_name, **extra_fields)

        return user


class CustomUser(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    initials = models.CharField(max_length=3, null=True, blank=True)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    start_date = models.DateTimeField(default=timezone.now)
    role = models.CharField(max_length=30, null=True, blank=True)
    permissions = models.JSONField(null=True, blank=True)
    otp = models.CharField(max_length=6, null=True, blank=True)
    avatar = models.JSONField(null=True, blank=True)
    username = None

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def get_full_name(self):
        return self.first_name + ' ' + self.last_name

    def __str__(self):
        return self.email


class UserSession(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40)
    login_time = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)


class SystemAlert(models.Model):
    message = models.TextField(blank=True)
    is_active = models.BooleanField(default=False)
