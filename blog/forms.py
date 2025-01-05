from django import forms
from django.contrib.auth.models import User
from .models import StudentProfileDetails,TeacherProfileDetails,Post

class StudentProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = StudentProfileDetails
        fields = ['image', 'studying_year', 'department', 'phone_number', 'parents_number']


class TeacherProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = TeacherProfileDetails
        fields = ['roll_number', 'department', 'phone_number', 'role', 'image']

class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username']  # Allow updating the username



class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ['title', 'content']

class PostUpdateForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ['title', 'content']  # Fields that can be updated
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'content': forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
        }



from django import forms
from .models import EmergencyMessage


class EmergencyMessageForm(forms.ModelForm):
    class Meta:
        model = EmergencyMessage
        fields = ['problem']  # Only the problem field is exposed in the form
        widgets = {
            'problem': forms.Textarea(attrs={
                'rows': 5,
                'cols': 50,
                'placeholder': 'Describe your emergency...',
                'class': 'form-control'
            }),
        }
