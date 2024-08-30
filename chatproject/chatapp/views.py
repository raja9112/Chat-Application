from django.shortcuts import redirect, render
from django.views import View
from django.contrib import auth, messages
from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin


# Create your views here.

class Home(View):
    def get(self, request):
        return render(request, 'index.html')
    def post(self, request):
        pass


# Password change password operation
# @login_required               # We cannot directly apply login_required decorator to CBV's instead we can use mixins
class ChangePassword(LoginRequiredMixin, View):
    def get(self, request):
        context = {
            'current_user': request.user
            }
        return render(request, 'auth-changepassword.html', context)
    
    def post(self, request):
        current_password = request.POST.get('currentpassword')
        new_password = request.POST.get('newpassword')
        confirm_password = request.POST.get('confirmnewpassword')

        current_user = request.user

        # Check if current password is matching
        if not current_user.check_password(current_password):
            messages.error(request, 'Current password is wrong')
            return redirect('/auth-changepassword')
        
        # Check if new passwords are matching
        if new_password != confirm_password:
            messages.error(request, "Passwords did not match. Please tryy again")
            return redirect('/auth-changepassword')
        
        # Update the user's password
        current_user.set_password(confirm_password)
        current_user.save()

        # Update the session to prevent logout after password change
        update_session_auth_hash(request, current_user)

        messages.success(request, "Your password has been sucessfully updated!")
        return redirect('/')
    


# Logout operation
def Logout(request):
     auth.logout(request)
     return render(request, 'auth-logout.html')


# Login operation
class Login(View):
    def get(self, request):
        current_user = request.user

        if current_user.id:
            messages.success(request, "Already logged in!")
            return redirect('/')
        else:
            return render(request, 'auth-login.html')
    
    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get("password")

        user_login = auth.authenticate(
            username=username, 
            password=password)
        
        # Check if user exists otherwise throw exception
        if user_login is not None:
            auth.login(request, user_login)
            messages.success(request, "Welcome back to Kooku!")
            return redirect('/')
        else:
            messages.error(request, "Username or Password is incorrect")
            return redirect('/auth-login')


# Registration operations
class Register(View):
    def get(self, request):
        return render(request, 'auth-register.html')
    
    def post(self, request):
        email = request.POST.get('email')
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirmpassword = request.POST.get('confirmpassword')

        if password == confirmpassword:
            # Check if username or email already exists
            if User.objects.filter(username=username).exists():
                messages.error(request, "Username already taken. Please try again.")
                return redirect('/auth-register/')
            elif User.objects.filter(email=email).exists():
                messages.error(request, "Email already taken. Please try again.")
                return redirect('/auth-register/')
            else:
                # Create user
                creating_user = User.objects.create_user(
                    username=username, 
                    email=email, 
                    password=password)
                
                creating_user.save()

                # Log the user in
                auth.login(request, creating_user)
                messages.success(request, "Welcome to Kooku, an App by Tea Kadai!")
                return redirect('/')
        else:
            messages.error(request, "Passwords did not match. Please try again.")
            return redirect('/auth-register/')
 

class Recover_password(View):
    def get(self, request):
        return render(request, 'auth-recoverpw.html')
    def post(self, request):
        pass