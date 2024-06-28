from django.db import models
from django.utils import timezone
from django.conf import settings

User = settings.AUTH_USER_MODEL

# Create your models here.

class History(models.Model):
    """ History of of result """
    input = models.TextField()
    output = models.TextField()
    create_at = models.DateTimeField(auto_now=timezone.now())
    accuracy = models.DecimalField(decimal_places=2, null=True, max_digits=5)
    is_deleted = models.BooleanField( null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self) :
        return self.output
    
