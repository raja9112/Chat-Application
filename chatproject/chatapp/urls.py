from django.urls import path
from .import views
from .views import Home, ChangePassword, Login, Register, Recover_password

urlpatterns = [
    path('', Home.as_view(), name = "HomePage"),
    path('auth-changepassword/', ChangePassword.as_view(), name= 'Change password'),
    path('auth-logout/', views.Logout, name= "Logout page"),
    path('auth-login/', Login.as_view(), name="Login page"),
    path('auth-register/', Register.as_view(), name="Registration page"),
    path('auth-recoverpw/', Recover_password.as_view(), name="Forget password page"),
    path('password-reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
]