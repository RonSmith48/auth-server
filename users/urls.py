from django.urls import path
import users.views as v
from users.admin_views import set_maintenance_mode, active_sessions, set_alert, create_user, admin_change_password

urlpatterns = [
    path('activate/', v.ActivateUserView.as_view(), name='activate'),
    # path('change-password/', v.change_password),
    path('login/', v.LoginView.as_view(), name='login'),
    path('register/', v.RegisterUserView.as_view(), name='register'),
    path('sudo/set-maintenance/', set_maintenance_mode),
    path('sudo/active-sessions/', active_sessions),
    path('sudo/set-alert/', set_alert),
    path('sudo/create-user/', create_user),
    path('sudo/change-password/', admin_change_password),
    # path('system-message/', v.system_message_view),
    path('token-refresh/', v.CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('token-verify/', v.VerifyTokenView.as_view(), name='token_verify'),
    path('update/', v.UpdateProfileView.as_view(), name='update'),
    path('user/<int:id>', v.UserView.as_view(), name='user'),
]
