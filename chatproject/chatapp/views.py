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
            if User.objects.filter(username = username).exists():
                messages.error(request, "Username already taken. Please try again")
            creating_user = User.objects.create_user(username = username, email= email , password = confirmpassword)
            creating_user.save()

            auth.login(request, creating_user)
            messages.success(request, "Welcome to Kooku, An App by Tea Kadai!")
            return redirect('/')
        
        messages.info(request, "Password did not match")
        return redirect('auth-register/')


class Recover_password(View):
    def get(self, request):
        return render(request, 'auth-recoverpw.html')
    def post(self, request):
        pass