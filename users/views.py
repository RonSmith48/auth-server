from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError, MultipleObjectsReturned
from django.core.mail import send_mail
from django.db import DatabaseError
from jwt.exceptions import ExpiredSignatureError
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework.views import APIView
from users.avatar_colours import AvatarColours

import random
import users.models as m
import users.serializers as s

User = get_user_model()

# ─── Authentication ────────────────────────────────────────────────────────────


class ActivateUserView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []   # skip JWT auth here

    def post(self, request):
        try:
            data = request.data
            serializer = s.VerifyAccountSerializer(data=data)

            if serializer.is_valid():
                user = User.objects.get(
                    email=serializer.validated_data['email'])
                user.is_active = True
                user.save()

                return Response({'msg': {'type': 'success', 'body': 'Account activation successful'}}, status=status.HTTP_200_OK)

            # logged in serializer
            errors = serializer.errors
            error_str = '\n'.join(
                [f"{field}: {', '.join(messages)}" for field, messages in errors.items()])
            return Response({'msg': {'type': 'error', 'body': error_str}}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            # logged in serializer
            return Response({'msg': {'type': 'error', 'body': 'Invalid email'}}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'msg': {'type': 'error', 'body': 'Account activation failed'}}, status=status.HTTP_200_OK)


class LoginView(TokenObtainPairView):
    serializer_class = s.CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        print("authenticating user")
        serializer = self.get_serializer(data=request.data)
        try:

            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            user_instance = data['user']
            serialized_user = s.UserSerializer(user_instance).data

            tokens = {'refresh': data['refresh'], 'access': data['access']}

            return Response({'tokens': tokens, 'user': serialized_user}, status=status.HTTP_200_OK)
        except AuthenticationFailed as e:
            # logged in serializer
            return Response({'msg': {'type': 'error', 'body': str(e)}}, status=status.HTTP_401_UNAUTHORIZED)


class RegisterUserView(APIView):
    serializer_class = s.RegisterUserSerializer
    permission_classes = [AllowAny]
    authentication_classes = []   # skip JWT auth here

    def post(self, request):
        try:
            serializer = s.RegisterUserSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()

            if not user.initials:
                user.initials = self.generate_initials(
                    user.first_name or '', user.last_name or '')

            bg, fg = AvatarColours.get_random_avatar_color()
            user.avatar = {
                "fg_colour": fg,
                "bg_colour": bg,
                "filename": None,
            }
            user.save()

            err = self.send_otp_email(request, user.email)
            if err:
                user.delete()

                if isinstance(err, dict) and 'msg' in err:
                    return Response(err, status=status.HTTP_200_OK)

                fallback_msg = {'msg': {
                    'type': 'error', 'body': 'We couldn’t send your OTP email. Please try again.'}}
                return Response(fallback_msg, status=status.HTTP_200_OK)

            return Response({'data': serializer.data}, status=status.HTTP_201_CREATED)

        except ValidationError as ve:
            # Check for specific known cases
            if 'email' in ve.detail and 'already exists' in str(ve.detail['email']):
                return Response({'msg': {'type': 'error', 'body': 'This email address is already registered.'}}, status=status.HTTP_200_OK)

            # Fallback to general validation message
            return Response({'msg': {'type': 'error', 'body': 'Invalid input. Please check the form and try again.'}}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'msg': {'type': 'error', 'body': 'Something went wrong during registration'}}, status=status.HTTP_200_OK)

    def send_otp_email(self, request, email):
        subject = 'Your account verification email'
        otp = random.randint(1000, 9999)
        message_body = f'Your OTP is {otp}'
        try:
            email_from = 'caveman@evolutionmining.com'
            send_mail(subject, message_body, email_from, [email])

            try:
                user_obj = User.objects.get(email=email)
                user_obj.otp = otp
                user_obj.save()

            except User.DoesNotExist:
                print('Unable to store OTP in database')
                return {'msg': {'type': 'error', 'body': 'There is a database error'}}

        except Exception as e:
            print('Unable to send OTP email')
            return {'msg': {'type': 'error', 'body': 'Mail server is not responding'}}

    def generate_initials(self, first_name, last_name):
        return f"{(first_name[:1] + last_name[:1]).upper()}" if first_name and last_name else "??"


class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = TokenRefreshSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        # Use the built-in TokenRefreshSerializer to handle the refresh process
        serializer = self.get_serializer(data=request.data)

        try:
            # Validate the refresh token
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            return Response(data, status=status.HTTP_200_OK)

        except ExpiredSignatureError:
            # Handle expired token case

            return Response({'msg': {'type': 'error', 'body': 'Refresh token has expired. Please log in again.'}},
                            status=status.HTTP_401_UNAUTHORIZED)

        except (TokenError, InvalidToken):
            # Handle invalid token case
            return Response({'msg': {'type': 'error', 'body': 'Invalid refresh token. Please try logging in again.'}},
                            status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            # Catch any other general exceptions
            return Response({'msg': {'type': 'error', 'body': 'An unexpected error occurred.'}},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyTokenView(APIView):
    """
    This endpoint checks if the provided access token is valid.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        If the request is authenticated, the token is valid.
        Otherwise, return a 401 error.
        """
        return Response({'msg': {'type': 'success', 'body': 'Token is valid'}}, status=status.HTTP_200_OK)


class UpdateProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        if not request.user or not request.user.is_authenticated:
            return Response({'msg': {'type': 'error', 'body': 'Authentication required'}}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user = request.user  # The authenticated user
            serializer = s.UpdateUserProfileSerializer(
                user, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response({'msg': {'type': 'success', 'body': 'Profile updated successfully'}}, status=status.HTTP_200_OK)

        except DatabaseError:
            return Response({'msg': {'type': 'error', 'body': 'Database error: Unable to update user profile'}}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'msg': {'type': 'error', 'body': 'Server error: Failed to update user profile'}}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserView(APIView):
    def get(self, request, id):
        try:
            user_obj = User.objects.get(id=id)
            serializer = s.UserSerializer(user_obj)
            return Response({'data': serializer.data}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'msg': {'type': 'error', 'body': 'User not found'}}, status=status.HTTP_404_NOT_FOUND)

        except MultipleObjectsReturned:
            # This shouldn't be possible
            return Response({'msg': {'type': 'error', 'body': 'Multiple users found with same ID'}}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({'msg': {'type': 'error', 'body': 'Could not retrieve user'}}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
