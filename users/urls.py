from django.urls import path
from users.views import login_view, logout_view, me_view, profile_view, register_view, verify_view, change_password, system_message_view
from users.admin_views import set_maintenance_mode, active_sessions, set_alert, create_user, admin_change_password

urlpatterns = [
    path('login/', login_view),
    path('logout/', logout_view),
    path('me/', me_view),
    path('profile/', profile_view),
    path('register/', register_view),
    path('verify/', verify_view),
    path('change-password/', change_password),
    path('system-message/', system_message_view),
    path('sudo/set-maintenance/', set_maintenance_mode),
    path('sudo/active-sessions/', active_sessions),
    path('sudo/set-alert/', set_alert),
    path('sudo/create-user/', create_user),
    path('sudo/change-password/', admin_change_password),
]
