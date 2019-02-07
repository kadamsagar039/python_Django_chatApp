from django.http import HttpResponsePermanentRedirect
from django.urls import reverse
from django.contrib.auth import get_user_model, login
import jwt
from django.http import HttpResponse
from django.shortcuts import render
from django.contrib.auth import authenticate
from .forms import SignupForm
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.contrib.auth.models import User
from django.core.mail import EmailMessage


# this is homepage
def index(request):
    return render(request, 'index.html', {})


# login page
def login_u(request):
    return render(request, 'login.html', {})


User = get_user_model()  # will retrieve the USER model class from django.


def Signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)  # takes signup data from user
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # user disabled
            user.save()  # stores in database.
            message = render_to_string('acc_email.html', {
                'user': user,
                'domain': 'http://127.0.0.1:8000',
                'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),  # because django 2.0.0
                'token': account_activation_token.make_token(user),
            })
            mail_subject = 'Activate your Fundoo account.'  # mail subject
            to_email = form.cleaned_data.get('email')  # mail id to be sent to
            email = EmailMessage(mail_subject, message,
                                 to=[to_email])  # takes 3 arguments mail_subject, message, mail_id to send
            email.send()  # sends mail
            return HttpResponse('The confirmation link has been sent to your mail id..\n'
                                'Please click on given link and confirm your registration....')

    else:
        # if signup not success
        form = SignupForm()

        # render signup.html
    return render(request, 'signup.html', {'form': form})


def activate(uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        print('Uid:             :', uid)
        user = User.objects.get(pk=uid)  # gets the username
        print('user:::::', user)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponsePermanentRedirect(reverse('sign_in'))
    else:
        return HttpResponse('Activation link is invalid!')


def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        login(request, user)
        if user:
            if user.is_active:
                # login(user)
                payload = {'username': username,
                           'password': password, }

                jwt_token = {'token': jwt.encode(payload, "secret_key", algorithm='HS256')}
                return render(request, 'chat.html', {})
                # return HttpResponse(jwt_token.values())
            else:
                return HttpResponse("Your account was inactive.")
        else:
            return HttpResponse("Invalid login details given")

    else:
        return render(request, 'login.html', {})
