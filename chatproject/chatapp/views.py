from django.shortcuts import redirect, render
from django.views import View
from django.contrib import auth, messages
from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib import messages
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site

# Create your views here.

class Home(LoginRequiredMixin, View):
    login_url = '/auth-login/'
    def get(self, request):
        return render(request, 'index.html')
    def post(self, request):
        pass


# Password change password operation
# @login_required               # We cannot directly apply login_required decorator to CBV's instead we can use mixins
class ChangePassword(LoginRequiredMixin, View):
    login_url ='/auth-login'
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
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, 'No user with that email address exists.')
            print('No user with that email address exists.')
            return redirect('/auth-recoverpw')

        # Generate the password reset token
        token_generator = default_token_generator
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)

        # Build Email and rendering email template from html file
        current_site = get_current_site(request)
        subject = 'Password Reset Request'
        message = render_to_string('password_reset_email.html', {
            'user': user,
            'protocol': 'http' if not request.is_secure() else 'https',
            'domain': current_site.domain,
            'uid': uid,
            'token': token,
            'site_name': 'kooku',
        })

        # sending email to specific user
        send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])

        messages.success(request, 'Password reset email has been sent.')
        print('Password reset email has been sent.')
        return redirect('/auth-recoverpw')


def password_reset_confirm(request, uidb64, token):
    
    # urlsafe_base64_decode(uidb64): Decodes the base64-encoded user ID.
    # force_text(): Converts the decoded bytes to a string (use force_str() in newer Django versions).
    # User.objects.get(pk=uid): Retrieves the user with the decoded ID.
    # Exception Handling: Catches exceptions if decoding fails or the user does not exist, setting user to None if an error occurs.
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    #  Checks if the token is valid for the given user. This ensures the token is correct and has not expired.
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST.get('newpassword')
            confirm_password = request.POST.get('confirmnewpassword')

            # Checks if both passwords are same
            if new_password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'password_reset_confirm.html', {
                    'uidb64': uidb64,
                    'token': token
                })

            # Updating user's password
            user.set_password(new_password)
            user.save()

            # Update the session to prevent logout after password change
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password has been reset successfully.')
            print('Your password has been reset successfully.')
            return redirect('/')

        return render(request, 'password_reset_confirm.html', {
            'uidb64': uidb64,
            'token': token
        })

    else:
        messages.error(request, 'The password reset link is invalid or has expired.')
        print('The password reset link is invalid or has expired.')
        return redirect('auth-recoverpw.html')
