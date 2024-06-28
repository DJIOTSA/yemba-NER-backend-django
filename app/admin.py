from django.contrib import admin
from .models import History

# Register your models here.


@admin.register(History)
class CategoryAdmin(admin.ModelAdmin):
    list_display =['id', 'create_at','accuracy', 'output', 'is_deleted']
