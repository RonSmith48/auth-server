from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()


class UpdateUserProfileSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='get_full_name', read_only=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name',
                  'initials', 'role', 'avatar', 'full_name']

    def validate_first_name(self, value):
        return value.capitalize()

    def validate_last_name(self, value):
        return value.capitalize()

    def update(self, instance, validated_data):
        for attr in ['first_name', 'last_name', 'initials', 'role']:
            if attr in validated_data:
                setattr(instance, attr, validated_data[attr])
        avatar = validated_data.get('avatar', instance.avatar)
        instance.avatar = avatar or None
        instance.save()
        return instance


class RegisterUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name',
                  'password', 'initials', 'role']
        extra_kwargs = {
            'password': {'write_only': True},
            'initials': {'required': False}
        }

    def validate_first_name(self, value):
        return value.capitalize()

    def validate_last_name(self, value):
        return value.capitalize()

    def create(self, validated_data):
        # 1. Remove password and initials so they don't collide
        password = validated_data.pop('password')
        validated_data.pop('initials', None)

        # 3. Create user—initials only passed once
        user = User.objects.create_user(
            **validated_data,   # email, first_name, last_name, role
            password=password
        )
        return user


class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        exclude = ['password', 'otp']

    def get_full_name(self, obj):
        return obj.get_full_name()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'email'

    def validate(self, attrs):
        credentials = {
            'email': attrs.get('email'),
            'password': attrs.get('password')
        }

        user = authenticate(**credentials)

        if user:
            if not user.is_active:
                raise AuthenticationFailed('Account is not activated')

            refresh = self.get_token(user)
            data = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': user,
            }

            return data
        else:
            raise AuthenticationFailed('User not registered')


class VerifyAccountSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            raise serializers.ValidationError(
                "Invalid email or user does not exist.")

        if user.otp != data['otp']:
            raise serializers.ValidationError("Incorrect verification code.")

        if user.is_active:
            raise serializers.ValidationError(
                "User account is already active.")

        return data

    def save(self):
        user = User.objects.get(email=self.validated_data['email'])
        user.is_active = True
        user.otp = ''
        user.save()
        return user
