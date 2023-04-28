"""kpm URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.contrib.auth import views as auth_views
from passwords import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.home, name='home'),
    path('about', views.about, name='about'),
    # Passwords
    path('admin/', admin.site.urls),
    path('view_passwords', views.view_stored_passwords, name='view-stored-passwords'),
    path('add_password', views.add_password, name='add-stored-password'),
    path('delete/<int:delete_id>', views.delete, name='delete-password'),
    path('delete-dialog/<int:delete_id>', views.delete_confirmation, name='delete-password-dialog'),
    path('update_stored_password/<int:update_id>', views.update_stored_password, name='update-stored-password'),
    path('update_user', views.update_user_details, name='update-user'),
    path('update_password', views.update_password, name='update-password'),
    path('register', views.register, name='register'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('login', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('logout', auth_views.LogoutView.as_view(template_name='logout.html'), name='logout'),
    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='password_reset.html'),
         name='password-reset'),
    path('password_reset/sent/',
         auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'),
         name='password_reset_done'),
    path('password_reset_confirm/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'),
         name='password_reset_confirm'),
    path('password_reset_complete',
         auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'),
         name='password_reset_complete'),
    path('profile', views.profile, name='profile')
]+ static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
