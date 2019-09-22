from django.db import models

# Create your models here.

class user_detail(models.Model):
   username = models.CharField(max_length = 50)
   password = models.CharField(max_length = 50)
   email_address=models.CharField(max_length=50)
   phonenumber = models.IntegerField()

   def __str__(self):
       return "username : {0} , password: {1} , email_address :  {2} , phonenumber : {3}".format(
           self.username, self.password, self.email_address,
           self.phonenumber)

   class Meta:
      db_table = "user_details"