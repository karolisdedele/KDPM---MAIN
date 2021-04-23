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
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.contrib.auth import get_user_model
User = get_user_model()
# apps
from .forms import CustomUserCreationForm, CustomUserChangeForm
from .models import StoredPasswords
from .password_generator import pw_generator


def aes_action(request, input, decrypt, salt, iv):
    """
    Encrypts or decrypts data from db
    :param request:
    :param input: Enter plaintext or cipher
    :param decrypt: False - encrypt, True - decrypt
    :return:
    """
    a = '{}{}'.format(request.user.email, request.user.username)
    # Get 32bit length password hash with MD5:
    password = md5(a.encode()).hexdigest()
    # Generate and return AES key from password hash and salt
    key = PBKDF2(password, salt).read(32)
    # Generate AES CTR block:
    aes = AESModeOfOperationCTR(key, Counter(iv))
    # Decrypt input if decrypt variable is set to True...
    if decrypt:
        return aes.decrypt(input).decode()
    # ... otherwise, encrypt input
    return aes.encrypt(input)


def generate_password(request):
    if request.method == 'POST' and 'run_script' in request.POST:
        pw_generator()
    return render(request, 'Generate_password.html', context={'title': 'Password Generator'})


def home(request):
    return render(request, 'home.html', context={'title': 'Welcome to KPM'})

def about(request):
    return render(request, 'about.html', context={'title': 'about'})

@login_required
def add_password(request):
    if request.method == 'POST':
        platform = request.POST.get('platform')
        account = request.POST.get('account')
        password = request.POST.get('password')
        print(platform, account, password)
        salt = urandom(16)
        print(type(salt))
        iv = randbits(256)
        encrypted_password = aes_action(request, password, salt=salt, iv=iv, decrypt=0)
        StoredPasswords.objects.create(
            platform=platform,
            account=account,
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
        'account': foo.account,
        'password': aes_action(request, input=foo.password, decrypt=True, salt=foo.salt, iv=int(foo.iv))}
        for foo in StoredPasswords.objects.filter(owner=request.user)]

    return render(request, 'password_viewer.html', context={'title': 'Stored passwords', 'passwords': passwords})


@login_required
def update_user_details(request):
    if request.method == 'POST':
        deciphered_passwords = [
            (foo.id,
             aes_action(request, input=foo.password, decrypt=True, salt=foo.salt, iv=int(foo.iv)))
            for foo in StoredPasswords.objects.filter(owner=request.user)
        ]
        form = CustomUserChangeForm(request.POST, instance=request.user)
        if form.is_valid():

            form.save()
            for pass_id, pwd in deciphered_passwords:
                entry = StoredPasswords.objects.get(id=pass_id)
                entry.password = aes_action(request, input=pwd, salt=entry.salt, iv=int(entry.iv), decrypt=False)
                entry.save()
            messages.add_message(request, messages.INFO, 'Password updated successfully')
        else:
            messages.add_message(request, messages.WARNING, 'Password could not be changed')
        return redirect('view-stored-passwords')
    else:
        return render(request, 'form_template.html',
                      context={'title': 'Update password',
                               'form': CustomUserChangeForm(instance=request.user)})


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
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk = uid)
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
        account = request.POST.get('account')
        password = request.POST.get('password')
        if account != stored_password.account:
            stored_password.account = account
            stored_password.save()
        old_password = aes_action(request, input=stored_password.password, decrypt=True, salt=stored_password.salt,
                                  iv=int(stored_password.iv))
        if password != old_password:
            salt = urandom(16)
            iv = randbits(256)
            encrypted_password = aes_action(request, password, salt=salt, iv=iv, decrypt=0)
            stored_password.password = encrypted_password
            stored_password.salt = salt
            stored_password.iv = str(iv)
            stored_password.save()

        messages.add_message(request, messages.SUCCESS, 'Password updated successfully')

    return render(request, 'add_password.html', context={
        'title': 'Update Account Data',
        'purpose': 'Updated selected account data',
        'account': stored_password.account,
        'password': aes_action(request, input=stored_password.password, decrypt=True, salt=stored_password.salt,
                               iv=int(stored_password.iv))
    })
