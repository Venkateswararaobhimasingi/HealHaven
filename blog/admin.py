from django.contrib import admin
from .models import OTP,StudentProfileDetails,TeacherProfileDetails,Post,Reply,Message,EmergencyMessage
# Register your models here.

admin.site.register(OTP)
admin.site.register(StudentProfileDetails)
admin.site.register(TeacherProfileDetails)
admin.site.register(Post)
admin.site.register(Reply)
admin.site.register(Message)
admin.site.register(EmergencyMessage)