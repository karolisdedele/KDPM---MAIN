from django.db import models
from django.contrib.auth.models import AbstractUser


# Create your models here.
class CustomUser(AbstractUser):
    username = models.CharField(max_length=256, unique=True)
    email = models.EmailField()


class StoredPasswords(models.Model):
    platform = models.CharField(max_length=256)
    account = models.BinaryField(max_length=1024,editable=True)
    password = models.BinaryField(max_length=1024)
    owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    # iv = models.BigIntegerField(default=secrets.randbits(256), editable=False)
    # Converting to string because SQLite does not support large integers
    iv = models.CharField(max_length=80, editable=False)
    salt = models.BinaryField()

    def __str__(self):
        return 'Owner: {}, Account name: {}'.format(self.owner, self.account)

    class Meta:
        verbose_name = 'Stored Password'
        verbose_name_plural = 'Stored Passwords'
