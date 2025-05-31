from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.http import JsonResponse, HttpResponseForbidden
from django.utils.timezone import now
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.parsers import JSONParser

from .models import SystemAlert, UserSession
from .serializers import (
    RegisterUserSerializer,
    VerifyAccountSerializer,
    UserSerializer,
    UpdateUserProfileSerializer
)

import json

# ─── Authentication ────────────────────────────────────────────────────────────


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):

    # DRF will parse JSON into request.data
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({'detail': 'Email and password required'}, status=status.HTTP_400_BAD_REQUEST)

    # Pass request into authenticate
    user = authenticate(request, username=email, password=password)
    if user is None:
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    login(request, user)
    return Response({'detail': 'Login successful'})


@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    logout(request)
    return JsonResponse({'detail': 'Logged out'})

# ─── “Who Am I” & Profile ──────────────────────────────────────────────────────


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def me_view(request):
    """
    Return the authenticated user’s data using UserSerializer,
    excluding sensitive fields and including full_name.
    """
    serializer = UserSerializer(request.user)
    return Response(serializer.data)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def profile_view(request):
    if request.method == 'GET':
        serializer = UserSerializer(request.user)
        return JsonResponse(serializer.data, safe=False)
    # PUT
    serializer = UpdateUserProfileSerializer(
        request.user, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return JsonResponse(serializer.data)
    return JsonResponse(serializer.errors, status=400)

# ─── Registration & Verification ────────────────────────────────────────────────


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    serializer = RegisterUserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return JsonResponse({'detail': 'Registration successful, check your email for the code'}, status=201)
    return JsonResponse(serializer.errors, status=400)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def verify_view(request):
    serializer = VerifyAccountSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return JsonResponse({'detail': 'Account verified, you can now log in'})
    return JsonResponse(serializer.errors, status=400)

# ─── Password Change ────────────────────────────────────────────────────────────


@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    if settings.AUTH_MODE != 'HOME':
        return HttpResponseForbidden('Password change not allowed in this mode.')
    data = JSONParser().parse(request)
    old_pw = data.get('old_password')
    new_pw = data.get('new_password')
    if not request.user.check_password(old_pw):
        return JsonResponse({'detail': 'Incorrect current password'}, status=400)
    try:
        validate_password(new_pw, request.user)
        request.user.set_password(new_pw)
        request.user.save()
        update_session_auth_hash(request, request.user)
        return JsonResponse({'detail': 'Password changed successfully'})
    except ValidationError as e:
        return JsonResponse({'detail': e.messages}, status=400)

# ─── System Alert ───────────────────────────────────────────────────────────────


@api_view(['GET'])
@permission_classes([AllowAny])
def system_message_view(request):
    alert = SystemAlert.objects.filter(is_active=True).first()
    return JsonResponse({'message': alert.message if alert else ''})
