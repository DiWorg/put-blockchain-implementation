from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin, UserAdmin
from django.contrib.auth.models import User

from .models import *

admin.site.register(Block)
admin.site.register(UserProfile)
admin.site.register(Transaction)
admin.site.register(Vote)


