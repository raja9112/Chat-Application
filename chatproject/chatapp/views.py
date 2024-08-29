from django.shortcuts import redirect, render
from django.views import View
from django.contrib import auth, messages
from django.contrib.auth.models import User

# Create your views here.

class Home(View):
    def get(self, request):
        return render(request, 'index.html')
    def post(self, request):
        pass

class ChangePassword(View):
    def get(self, request):
        return render(request, 'auth-changepassword.html')
    def post(self, request):
        pass

class Logout(View):
    def get(self, request):
        return render(request, 'auth-logout.html')
    def post(self, request):
        pass

class Login(View):
    def get(self, request):
        return render(request, 'auth-login.html')
    
    def post(self, request):
        pass

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