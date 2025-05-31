# users/serializers.py
from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers

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
        password = validated_data.pop('password')
        initials = validated_data.get('initials') or (
            f"{validated_data['first_name'][0]}{validated_data['last_name'][0]}".upper(
            )
        )
        validated_data['initials'] = initials
        user = User.objects.create_user(
            email=validated_data['email'],
            password=password,
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            initials=initials,
            role=validated_data.get('role'),
        )
        return user


class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        exclude = ['password', 'otp']

    def get_full_name(self, obj):
        return obj.get_full_name()


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
