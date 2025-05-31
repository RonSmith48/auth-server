from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponseForbidden
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth import get_user_model
from .models import SystemAlert, UserSession
import json
import os

User = get_user_model()


def is_local_mode():
    return os.getenv('AUTH_MODE', 'HOME') == 'HOME'


def staff_required(view_func):
    return user_passes_test(lambda u: u.is_staff)(view_func)


@csrf_exempt
@staff_required
def set_maintenance_mode(request):
    data = json.loads(request.body)
    mode = data.get('mode') == 'true'
    os.environ['MAINTENANCE_MODE'] = 'true' if mode else 'false'
    return JsonResponse({'maintenance_mode': mode})


@staff_required
def active_sessions(request):
    sessions = list(UserSession.objects.values('user__username', 'last_seen'))
    return JsonResponse({'active_users': sessions})


@csrf_exempt
@staff_required
def set_alert(request):
    data = json.loads(request.body)
    msg = data.get('message')
    active = data.get('active')
    SystemAlert.objects.update_or_create(
        id=1, defaults={'message': msg, 'is_active': active})
    return JsonResponse({'status': 'updated'})


@csrf_exempt
@staff_required
def create_user(request):
    if not is_local_mode():
        return HttpResponseForbidden('Not allowed in this mode.')
    data = json.loads(request.body)
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return JsonResponse({'detail': 'Username and password required'}, status=400)
    if User.objects.filter(username=username).exists():
        return JsonResponse({'detail': 'User already exists'}, status=400)
    user = User.objects.create_user(username=username, password=password)
    return JsonResponse({'detail': f'User {username} created'})


@csrf_exempt
@staff_required
def admin_change_password(request):
    if not is_local_mode():
        return HttpResponseForbidden('Not allowed in this mode.')
    data = json.loads(request.body)
    username = data.get('username')
    new_pw = data.get('new_password')
    try:
        user = User.objects.get(username=username)
        user.set_password(new_pw)
        user.save()
        return JsonResponse({'detail': f'Password updated for {username}'})
    except User.DoesNotExist:
        return JsonResponse({'detail': 'User not found'}, status=404)
