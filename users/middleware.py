from django.utils.timezone import now
from django.contrib.sessions.models import Session
from users.models import UserSession


class LastSeenMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            session_key = request.session.session_key
            UserSession.objects.update_or_create(
                user=request.user, session_key=session_key,
                defaults={'last_seen': now()}
            )
        return self.get_response(request)
