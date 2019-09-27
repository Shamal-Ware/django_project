from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class user_detail(models.Model):
   user = models.OneToOneField(User, on_delete=models.CASCADE,related_name='tracks')
   phonenumber = models.IntegerField()

   def __str__(self):
       return str(self.user)

   class Meta:
      db_table = "user_details"