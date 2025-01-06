from django.db import models
from django.contrib.auth.models import User
from PIL import Image
from django.utils.timezone import now
import datetime
from django.utils import timezone
from django.urls import reverse


class OTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expiry_time = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.expiry_time:
            self.expiry_time = now() + datetime.timedelta(minutes=5)
        super().save(*args, **kwargs)



class StudentProfileDetails(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="student_profile")
    roll_number = models.CharField(max_length=20, unique=True)  
    studying_year = models.IntegerField(default=1)  
    department = models.CharField(max_length=100) 
    email = models.EmailField()  # Required during registration
    phone_number = models.CharField(max_length=15)  
    parents_number = models.CharField(max_length=15)  
    role = models.CharField(max_length=20, default='student')  # Defaults to "student"
    image = models.URLField(max_length=500, blank=True, null=True,default='https://i.imgur.com/7suwDp5.jpeg') 

    def __str__(self):
        return f'{self.user.username} Profile'

    

class TeacherProfileDetails(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="teacher_profile")
    roll_number = models.CharField(max_length=20, unique=True)
    department = models.CharField(max_length=100)  # Required during registration
    email = models.EmailField()  # Required during registration
    phone_number = models.CharField(max_length=15, null=True, blank=True)  # Optional
    role = models.CharField(max_length=20, default='teacher')  # Defaults to "teacher"
    image = models.URLField(max_length=500, blank=True, null=True,default='https://i.imgur.com/7suwDp5.jpeg') 

    def __str__(self):
        return f'{self.user.username} Profile'

    
      

# models.py

from django.contrib.auth.models import User
from django.db import models

class Post(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    date_posted = models.DateTimeField(auto_now_add=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    likes = models.PositiveIntegerField(default=0)
    dislikes = models.PositiveIntegerField(default=0)
    role = models.CharField(default='teacher', max_length=20)
    liked_by = models.ManyToManyField(User, related_name='liked_posts', blank=True)
    disliked_by = models.ManyToManyField(User, related_name='disliked_posts', blank=True)

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return reverse('post-detail', kwargs={"pk": self.pk})





class Reply(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='replies')
    content = models.TextField()
    date_posted = models.DateTimeField(default=timezone.now)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(default='teacher', max_length=20)

    def __str__(self):
        return f"Reply by {self.author} on {self.post.title}"




class Message(models.Model):
    sender_author = models.ForeignKey(User, related_name='sent_messages', on_delete=models.CASCADE)
    receiver_author = models.ForeignKey(User, related_name='received_messages', on_delete=models.CASCADE)
    sender_email = models.EmailField()
    receiver_email = models.EmailField()
    sender_role = models.CharField(max_length=50)
    receiver_role = models.CharField(max_length=50)
    subject = models.CharField(max_length=100)
    date = models.DateTimeField(auto_now_add=True)
    content = models.TextField()
    sender_status = models.CharField(max_length=20, default="unread")  # unread/read
    receiver_status = models.CharField(max_length=20, default="unread")  # unread/read
    

    def __str__(self):
        return f"Message from {self.sender_author} to {self.receiver_author} - {self.subject}"






from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now


from django.db import models
from django.utils.timezone import now

class EmergencyMessage(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
    ]

    # Details about the emergency
    problem = models.TextField()  # Problem description
    sent_time = models.DateTimeField(default=now)  # When the message was sent
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')  # Current status

    # User Details (auto-filled in views)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="emergency_sent")
    sender_role = models.CharField(max_length=50)  # e.g., 'student', 'teacher', 'doctor'
    sender_roll_number = models.CharField(max_length=50, default='000000') # Sender's roll number (if applicable)
    sender_department = models.CharField(max_length=100, default='Unknown')  # Sender's department
    sender_phone_number = models.CharField(max_length=15, blank=True, null=True)  # Sender's phone number (blank=True for migration)

    # Target recipients
    sent_to_role = models.CharField(max_length=50, default='student')  # Initially sent to 'doctor', then 'teacher' if not seen
    sent_to_user = models.ManyToManyField(User, related_name="emergency_received")

    # Reply and resolution
    reply = models.TextField(null=True, blank=True)  # Reply text
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="emergency_resolved")
    resolved_time = models.DateTimeField(null=True, blank=True)  # Time of resolution

    def __str__(self):
        return f"EmergencyMessage ({self.sender.username} - {self.problem[:30]})"
