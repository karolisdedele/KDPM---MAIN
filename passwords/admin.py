from django.contrib import admin
from .models import CustomUser, StoredPasswords

# Register your models here.
admin.site.register(CustomUser)


# admin.site.register(StoredPasswords)
@admin.register(StoredPasswords)
class StoredPasswordsAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    list_display_links = None
    list_display = ('id', 'owner', 'account', 'password')
    fieldsets = [
        ['', {'fields': ['account', 'password', 'owner', 'iv', 'salt']}]
    ]
    readonly_fields = ['account', 'password', 'owner', 'iv', 'salt']
