# python
from os import urandom
from hashlib import md5
from secrets import randbits
from pbkdf2 import PBKDF2
from pyaes import AESModeOfOperationCTR, Counter
# django
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.decorators import login_required
from django.core.mail import EmailMessage
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.contrib.auth import get_user_model

User = get_user_model()
# apps
from .forms import CustomUserCreationForm, CustomUserChangeForm
from .models import StoredPasswords
from .password_generator import pw_generator
# maybe it's fixed idk

def aes_action(request, input, decrypt, salt, iv):
    a = '{}{}'.format(request.user.email, request.user.username)
    # Get 32bit length password hash with MD5:
    password = md5(a.encode()).hexdigest()
    # Generate and return AES key from password hash and salt
    key = PBKDF2(password, salt).read(32)
    aes = AESModeOfOperationCTR(key, Counter(iv))
    if decrypt:
        return aes.decrypt(input).decode()
    return aes.encrypt(input)


def home(request):
    return render(request, 'home.html', context={'title': 'Welcome to KDPM'})


def about(request):
    return render(request, 'about.html', context={'title': 'About'})


@login_required
def add_password(request):
    if request.method == 'POST':
        platform = request.POST.get('platform')
        account = request.POST.get('account')
        password = request.POST.get('password')
        salt = urandom(16)
        iv = randbits(256)
        encrypted_account= aes_action(request, account, salt=salt, iv=iv, decrypt=False)
        encrypted_password = aes_action(request, password, salt=salt, iv=iv, decrypt=False)
        StoredPasswords.objects.create(
            platform=platform,
            account=encrypted_account,
            password=encrypted_password,
            salt=salt,
            iv=str(iv),
            owner=request.user
        )
        messages.add_message(request, messages.SUCCESS, 'Password added successfully')

    return render(request, 'add_password.html', context={
        'title': 'Add stored password',
        'purpose': 'Add new account data',
    })


@login_required
def view_stored_passwords(request):
    passwords = [{
        'id': foo.id,
        'platform': foo.platform,
        'account': aes_action(request, input=foo.account, decrypt=True, salt=foo.salt, iv=int(foo.iv)),
        'password': aes_action(request, input=foo.password, decrypt=True, salt=foo.salt, iv=int(foo.iv))
    }
        for foo in StoredPasswords.objects.filter(owner=request.user)]

    return render(request, 'password_viewer.html', context={'title': 'Stored passwords', 'passwords': passwords})


@login_required
def update_user_details(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.add_message(request, messages.INFO, 'Password updated successfully')
            return redirect('profile')
        else:
            messages.add_message(request, messages.WARNING, 'Error. One of the passwords was entered incorrectly.')
    else:
        form = PasswordChangeForm(request.user)
        return redirect('profile')



@login_required
def update_password(request):
    if request.method == 'POST':
        password_form = PasswordChangeForm(request.user, request.POST)
        if password_form.is_valid():
            password = password_form.save()
            update_session_auth_hash(request, password)
            messages.add_message(request, messages.SUCCESS, 'Password updated successfully')
        else:
            messages.add_message(request, messages.WARNING, 'Could not update password')
    else:
        messages.add_message(request, messages.WARNING, 'Wrong request')
    return redirect('profile')


def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            mail_subject = "Activate your KDPM account."
            message = render_to_string(
                'account_activate_email.html',
                {'user': user,
                 'domain': current_site.domain,
                 'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                 'token': account_activation_token.make_token(user), }
            )
            to_email = form.cleaned_data.get('email')
            email = EmailMessage(
                mail_subject, message, to=[to_email]
            )
            email.send()
            messages.success(request, ('Please Confirm your email to complete registration.'))
            return redirect('login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'input_model_form.html', {'form': form})


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        messages.success(request, ('Email verification successful'))
        return redirect('home')
    else:
        return messages.warning(request, ('Activation link is invalid'))


def profile(request):
    return render(request, 'profile.html', context={
        'title': 'Profile editor',
        'user_update_form': CustomUserChangeForm(instance=request.user),
        'password_update_form': PasswordChangeForm(request.user)
    })


def delete_confirmation(request, delete_id):
    a = StoredPasswords.objects.get(id=delete_id)
    return render(request, 'delete_alert.html', context={
        'account': a
    })


def delete(request, delete_id):
    StoredPasswords.objects.get(id=delete_id).delete()
    messages.add_message(request, messages.SUCCESS, 'The stored password was deleted')
    return redirect('view-stored-passwords')


def update_stored_password(request, update_id):
    stored_password = StoredPasswords.objects.get(id=update_id)
    if request.method == 'POST':
        platform = request.POST.get('platform')
        account = request.POST.get('account')
        password = request.POST.get('password')
        old_account = aes_action(request, input=stored_password.account, decrypt=True, salt=stored_password.salt,
                                  iv=int(stored_password.iv))
        old_password = aes_action(request, input=stored_password.password, decrypt=True, salt=stored_password.salt,
                                  iv=int(stored_password.iv))
        if password != old_password or account != old_account or platform != stored_password.platform:
            salt = urandom(16)
            iv = randbits(256)
            encrypted_password = aes_action(request, password, salt=salt, iv=iv, decrypt=False)
            encrypted_account = aes_action(request, account, salt=salt, iv=iv, decrypt=False)
            stored_password.platform = platform
            stored_password.password = encrypted_password
            stored_password.account = encrypted_account
            stored_password.salt = salt
            stored_password.iv = str(iv)
            stored_password.save()
        messages.add_message(request, messages.SUCCESS, 'Password updated successfully')
    return render(request, 'add_password.html', context={
        'title': 'Update Account Data',
        'purpose': 'Updated selected account data',
        'platform': stored_password.platform,
        'account': aes_action(request, input=stored_password.account, decrypt=True, salt=stored_password.salt,
                               iv=int(stored_password.iv)),
        'password': aes_action(request, input=stored_password.password, decrypt=True, salt=stored_password.salt,
                               iv=int(stored_password.iv))
    })

