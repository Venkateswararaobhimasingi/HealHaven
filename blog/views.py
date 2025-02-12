from django.shortcuts import render, redirect ,get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from django.contrib.auth import authenticate, alogin
from django.contrib.auth.hashers import check_password
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import authenticate, login as auth_login
from django.shortcuts import redirect, render
from django.contrib import messages
from django.contrib.auth.models import User
from django.http import JsonResponse
import time


from django.core.mail import send_mail
from django.conf import settings
import random

from django.utils.timezone import now
from django.core.mail import send_mail
from .models import OTP


from django.db.models.signals import post_save
from django.dispatch import receiver
# Import your profile models
from .models import StudentProfileDetails, TeacherProfileDetails 

from django.contrib.auth.decorators import login_required
from .forms import StudentProfileUpdateForm, UserUpdateForm ,TeacherProfileUpdateForm ,PostUpdateForm

from .models import Post,Reply
from .forms import PostForm

# Create your views here.
def home(request):
    if request.method == 'POST':
        name = request.POST['name']
    return render(request, 'blog/home.html')
def about(request):
    return render(request, 'blog/about.html')
    
def msg(request):
    current_user = request.user 

    
    return render(request, 'blog/msg.html', {'current_user': current_user})

def base(request):
   
    return render(request, 'blog/base.html')

def login(request):
    
    return render(request, 'blog/login.html')
def register(request):
    
    return render(request, 'blog/register.html')
def forgotpassword(request):
    
    return render(request, 'blog/forgotpassword.html')





# Student Registration
def register_student(request):
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']
        rollnumber = request.POST['rollnumber']

        # Check if the username or email already exists
        if User.objects.filter(username=name).exists():
            messages.error(request, 'A user with this username already exists.')
        elif User.objects.filter(email=email).exists():
            messages.error(request, 'A user with this email already exists.')
        elif StudentProfileDetails.objects.filter(roll_number=rollnumber).exists():
            messages.error(request, 'A user with this roll number already exists.')
        else:
            # Create the user
            user = User.objects.create_user(username=name, email=email, password=password)

            # Create the profile with type='teacher'
            StudentProfileDetails.objects.create(user=user,roll_number=rollnumber,email=email)

            messages.success(request, 'Student registered successfully.')
            return redirect('login')  # Redirect to the login page or desired page

    # Redirect to the registration page if not a POST request or if registration fails
    return redirect('register')


# Teacher/Doctor Registration



def register_teacher(request):
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']
        rollnumber = request.POST['rollnumber']

        # Check if the username or email already exists
        if User.objects.filter(username=name).exists():
            messages.error(request, 'A user with this username already exists.')
        elif User.objects.filter(email=email).exists():
            messages.error(request, 'A user with this email already exists.')
        elif TeacherProfileDetails.objects.filter(roll_number=rollnumber).exists():
            messages.error(request, 'A user with this roll number already exists.')
        else:
            # Create the user with superuser status
            user = User.objects.create_user(username=name, email=email, password=password)
            user.is_staff = True  # Allows access to admin site
            #user.is_superuser = True  # Grants superuser permissions
            user.save()

            # Create the profile with type='teacher'
            TeacherProfileDetails.objects.create(user=user, roll_number=rollnumber,email=email)

            messages.success(request, 'Teacher/Doctor registered successfully.')
            return redirect('login')  # Redirect to the login page or desired page

    # Redirect to the registration page if not a POST request or if registration fails
    return redirect('register')





# Student Login View

def student_login(request):
    if request.method == 'POST':  # Only process POST requests
        email = request.POST.get('email')
        password = request.POST.get('password')

        if request.user.is_authenticated:  # Check if the user is already logged in
            messages.error(request, 'You are already logged in!')
            return redirect('student_profile')  # Redirect to the dashboard page

        try:
            # Fetch the user object using email
            user = User.objects.get(email=email)

            # Check if the user has a StudentProfile
            if hasattr(user, 'student_profile'):
                # Authenticate the user with the username and password
                authenticated_user = authenticate(request, username=user.username, password=password)
                if authenticated_user is not None:
                    # Log the user in using Django's auth system
                    auth_login(request, authenticated_user)

                    messages.success(request, 'Student logged in successfully!')
                    return redirect('student_profile')  # Redirect to the student's home page
                else:
                    messages.error(request, 'Invalid password for student account.')
            else:
                messages.error(request, 'This account is not associated with a student.')
        except User.DoesNotExist:
            messages.error(request, 'No student account found with this email!')
    else:
        messages.error(request, 'Invalid request method.')

    return redirect('login')


def teacher_login(request):
    if request.method == 'POST':  # Only process POST requests
        email = request.POST.get('email')
        password = request.POST.get('password')

        if request.user.is_authenticated:  # Check if the user is already logged in
            messages.error(request, 'You are already logged in!')
            return redirect('teacher_profile')  # Redirect to the dashboard page

        try:
            # Fetch the user object using email
            user = User.objects.get(email=email)

            # Check if the user has a TeacherProfileDetails
            if hasattr(user, 'teacher_profile'):
                # Authenticate the user with the username and password
                authenticated_user = authenticate(request, username=user.username, password=password)
                if authenticated_user is not None:
                    # Log the user in using Django's auth system
                    auth_login(request, authenticated_user)

                    messages.success(request, 'Teacher logged in successfully!')
                    return redirect('teacher_profile')  # Redirect to the teacher's home page
                else:
                    messages.error(request, 'Invalid password for teacher account.')
            else:
                messages.error(request, 'This account is not associated with a teacher.')
        except User.DoesNotExist:
            messages.error(request, 'No teacher account found with this email!')
    else:
        messages.error(request, 'Invalid request method.')

    return redirect('login')



def user_logout(request):
    # Log out the user
    auth_logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return render(request, 'blog/logout.html')  # Redirect to the login page after logout

  



def msgcalled(request):
    """
    This view will print a message to the server console and return a response
    to the client (browser). The client is not affected; only the server logs the message.
    """
    # Python code that runs on the server side and prints to the server's console
    print(f"[INFO] msgcalled view has been triggered at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Return a JSON response to the client, so the browser stays unaffected
    response_data = {
        "message": "The server has processed your request.",
    }
    return JsonResponse(response_data)


def langu(request):
    
    return render(request, 'blog/langu.html')





def send_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        # Generate a random 6-digit OTP
        otp_code = f"{random.randint(100000, 999999)}"

        # Save or update OTP in the database
        otp, created = OTP.objects.update_or_create(
            email=email,
            defaults={'otp': otp_code, 'is_verified': False, 'created_at': now()},
        )

        # Prepare the email content
        subject = "Your HealHaven OTP Code"
        message = f"""
        Hello,

        Thank you for choosing HealHaven, your trusted companion for health and wellness. 

        Your OTP code is: {otp_code}. Please use this code to verify your account or reset your password. 
        Remember, this code is valid for 5 minutes only, so act promptly.

        At HealHaven, we prioritize your well-being and security. If you didn't request this email, please ignore it.

        Stay healthy and happy,
        The HealHaven Team
        """
        from_email = 'srinu19773@gmail.com'

        # Send the OTP via email
        try:
            send_mail(
                subject,
                message,
                from_email,
                [email],
                fail_silently=False,
            )
            messages.success(request, 'An OTP has been sent to your email. Please check your inbox.')
        except Exception as e:
            messages.error(request, f'Failed to send OTP: {e}')
            return redirect('send_otp')

        return redirect('verify_otp')

    return render(request, 'blog/send_otp.html')



def verify_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        otp_code = request.POST.get('otp')

        try:
            otp = OTP.objects.get(email=email)

            # Check if OTP is valid
            if otp.otp == otp_code and otp.expiry_time > now():
                otp.is_verified = True
                otp.save()

                # Set session to allow password reset
                request.session['otp_verified'] = True
                request.session['verified_email'] = email
                messages.success(request, 'OTP verified successfully!')
                return redirect('reset_password')

            messages.error(request, 'Invalid or expired OTP.')

        except OTP.DoesNotExist:
            messages.error(request, 'No OTP found for this email.')

    return render(request, 'blog/verify_otp.html')


def reset_password(request):
    if not request.session.get('otp_verified'):
        messages.error(request, 'Unauthorized access.')
        return redirect('send_otp')

    if request.method == 'POST':
        email = request.session.get('verified_email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            messages.error(request, 'Passwords do not match.')
        else:
            # Update user's password
            from django.contrib.auth.models import User

            try:
                user = User.objects.get(email=email)
                user.set_password(password1)
                user.save()

                # Invalidate session and delete OTP
                del request.session['otp_verified']
                OTP.objects.filter(email=email).delete()

                messages.success(request, 'Password reset successfully!')
                return redirect('login')
            except User.DoesNotExist:
                messages.error(request, 'User with this email does not exist.')

    return render(request, 'blog/reset_password.html')




def student_profile_view(request):
    student_profile = get_object_or_404(StudentProfileDetails, user=request.user)
    print(student_profile.email)
    context = {
        'profile': student_profile,
        'role': 'Student',
    }
    return render(request, 'blog/student_profile.html', context)

def teacher_profile_view(request):
    teacher_profile = get_object_or_404(TeacherProfileDetails, user=request.user)
    context = {
        'profile': teacher_profile,
        'role': 'Teacher',
    }
    return render(request, 'blog/teacher_profile.html', context)


import requests
from django.conf import settings

def upload_to_imgur(image_file):
    """
    Uploads an image file to Imgur and returns the public URL.
    """
    url = "https://api.imgur.com/3/image"
    headers = {
        "Authorization": f"Client-ID {settings.IMGUR_CLIENT_ID}"
    }

    try:
        # Upload image to Imgur
        response = requests.post(url, headers=headers, files={"image": image_file})
        response.raise_for_status()  # Will raise an HTTPError if the status code is not 2xx

        # Parse the response
        response_data = response.json()
        if response_data.get('success'):
            return response_data['data']['link']  # Return the public image URL
        else:
            raise Exception("Imgur API response indicates failure.")
    
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to upload image to Imgur: {str(e)}")

@login_required
def update_student_profile_view(request):
    student_profile = request.user.student_profile
    temp=student_profile.image
    user_form = UserUpdateForm(instance=request.user)
    profile_form = StudentProfileUpdateForm(instance=student_profile)

    if request.method == 'POST':
        user_form = UserUpdateForm(request.POST, instance=request.user)
        profile_form = StudentProfileUpdateForm(request.POST, request.FILES, instance=student_profile)

        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save(commit=False)
            user.username = user_form.cleaned_data['username']
            user.save()

            image_file = request.FILES.get('image')
            if image_file:
                try:
                    # Upload the image to Imgur
                    imgur_url = upload_to_imgur(image_file)
                    student_profile.image = imgur_url  # Set the image URL
                except Exception as e:
                    messages.error(request, f"Error uploading image: {str(e)}")
                    return redirect('update_student_profile')

            profile_form.save()
            if image_file==None:
                student_profile.image = temp
                student_profile.save()
            messages.success(request, 'Your profile has been updated successfully!')
            return redirect('student_profile')

    context = {
        'user_form': user_form,
        'profile_form': profile_form,
        'simg': student_profile.image if student_profile.image else 'https://i.imgur.com/7suwDp5.jpeg',
    }
    return render(request, 'blog/update_student_profile.html', context)

@login_required
def update_teacher_profile_view(request):
    teacher_profile = request.user.teacher_profile
    temp=teacher_profile.image
    
    user_form = UserUpdateForm(instance=request.user)
    profile_form = TeacherProfileUpdateForm(instance=teacher_profile)

    if request.method == 'POST':
        user_form = UserUpdateForm(request.POST, instance=request.user)
        profile_form = TeacherProfileUpdateForm(request.POST, request.FILES, instance=teacher_profile)

        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save(commit=False)
            user.username = user_form.cleaned_data['username']
            user.save()

            image_file = request.FILES.get('image')

            if image_file:
                try:
                    imgur_url = upload_to_imgur(image_file)
                    teacher_profile.image = imgur_url  # Update with new image if uploaded
                except Exception as e:
                    messages.error(request, f"Error uploading image: {str(e)}")
                    return redirect('update_teacher_profile')
           
                
           
            profile_form.save()  # Save with either a new or existing image
            if image_file==None:
                teacher_profile.image = temp
                teacher_profile.save()
            messages.success(request, 'Your profile has been updated successfully!')
            return redirect('teacher_profile')

    context = {
        'user_form': user_form,
        'profile_form': profile_form,
        'simg': teacher_profile.image if teacher_profile.image!=None else 'https://i.imgur.com/7suwDp5.jpeg',
    }
    return render(request, 'blog/update_teacher_profile.html', context)



@login_required
def post(request):
    posts = Post.objects.all().order_by('-date_posted')  # Display posts by date, most recent first
    return render(request, 'blog/post.html', {'posts': posts})

@login_required
def myposts(request):
    # Filter posts by the logged-in user and order by most recent
    user_posts = Post.objects.filter(author=request.user).order_by('-date_posted')
    return render(request, 'blog/post.html', {'posts': user_posts})



@login_required
def post_detail(request):
    if request.method == 'POST':
        post_id = request.POST['name']
        post = get_object_or_404(Post, id=post_id)

        if post.author == request.user:
            # If the post belongs to the current user, redirect to profile_detail.html
            return render(request, 'blog/post_detail.html', {'post': post})
        else:
            # If the post does not belong to the current user, get all posts by this author
            owner_posts = Post.objects.filter(author=post.author).order_by('-date_posted')
            return render(request, 'blog/post.html', {'posts': owner_posts,'author':post.author})
    else:
        # Default behavior (optional)
        posts = Post.objects.all().order_by('-date_posted')
        return render(request, 'blog/post_detail.html', {'posts': posts})



@login_required
def create_post(request):
    if request.method == 'POST':
        form = PostForm(request.POST)
        if form.is_valid():
            post = form.save(commit=False)
            post.author = request.user  # Assign the current user as the author

            # Try to find the user's profile based on the email address
            try:
                # Try to get teacher profile by matching email
                teacher_profile = TeacherProfileDetails.objects.get(user__email=request.user.email)
                #trole = get_object_or_404(User, email=request.user.email)
                post.role = teacher_profile.role  # Assign role 'teacher' if profile is found
                print(teacher_profile)
                print(f"User {request.user.email} is a teacher. or {teacher_profile.role}")  # Print the role
            except TeacherProfileDetails.DoesNotExist:
                try:
                    # Try to get student profile by matching email
                    student_profile = StudentProfileDetails.objects.get(user__email=request.user.email)
                    post.role = student_profile.role  # Assign role 'student' if profile is found
                    print(f"User {request.user.email} is a student.")  # Print the role
                except StudentProfileDetails.DoesNotExist:
                    # If no profile is found, default to 'student'
                    post.role = 'student'
                    print(f"User {request.user.email} does not have a specific profile, defaulting to student.")  # Print the role

            post.save()
            return redirect('post')  # Redirect to the home page after saving the post
    else:
        form = PostForm()

    return render(request, 'blog/create_post.html', {'form': form})




def post_update(request):

    if request.method == 'POST':
        id = request.POST['id']

    post = get_object_or_404(Post, id=id)

    # Ensure only the author of the post can update it
    if request.user != post.author:
        return redirect('home')  # Redirect if the user is not the author

    if request.method == 'POST':
        form = PostUpdateForm(request.POST, instance=post)
        if form.is_valid():
            updated_post = form.save(commit=False)
            updated_post.date_posted = now()  # Update the date to the current date
            updated_post.save()
            return redirect('post')  # Redirect to the post detail page
    else:
        form = PostUpdateForm(instance=post)

    return render(request, 'blog/post_update.html', {'form': form, 'post': post})


@login_required
def post_delete_view(request ):
    if request.method == 'POST':
        id1 = request.POST['id1']
    post = get_object_or_404(Post, id=id1)
    
    if request.method == 'POST' :
        if post.author == request.user:  # Ensure only the post author can delete
            return render(request, 'blog/post_delete.html', {'post': post})
        else:
            messages.error(request, "You are not authorized to delete this post.")
        return redirect('post')
    return redirect('post')

@login_required
def post_delete(request ):
    if request.method == 'POST':
        id = request.POST['id']
    post = get_object_or_404(Post, id=id)
    
    if request.method == 'POST' :
        if post.author == request.user:  # Ensure only the post author can delete
            post.delete()
            messages.success(request, "The post has been successfully deleted!")
        else:
            messages.error(request, "You are not authorized to delete this post.")
        return redirect('post')
    return render(request, 'blog/post_delete.html', {'post': post})


def chat(request):
    return render(request, 'blog/chat.html')


from django.http import JsonResponse
import google.generativeai as genai
import time
import logging
import json

# Configure Generative AI API key
genai.configure(api_key="AIzaSyDEV4I8_gmbwDN2eMfdHd_xBQaLzZ-oUoE")
model = genai.GenerativeModel("gemini-1.5-flash")

# Set up logging for debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def chatbot_response(request):
    if request.method == "POST":
        
        data = json.loads(request.body)
        user_message = data.get("message")

        if not user_message:
            return JsonResponse({"response": "I didn't get that. Could you please rephrase?"})

        # Add health-related context to the user message
        health_prompt = (
            "You are a helpful assistant specialized in health-related queries. "
            "Please answer the following question or request with health-related advice or information only: "
        )
        full_prompt = health_prompt + user_message

        # Retry mechanism in case of temporary issues
        max_retries = 1
        retry_delay = 2  # seconds
        for attempt in range(max_retries):
            try:
                logger.info(f"Attempt {attempt + 1}: Sending prompt to the AI model")
                ai_response = model.generate_content(full_prompt)

                # Replace newlines with meaningful breaks for the frontend
                response_text = ai_response.text.replace("\n", "*****")
                logger.info(f"AI Response gemini-1.5: {response_text}")
                return JsonResponse({"response": response_text})

            except Exception as e:
                logger.error(f"Error during AI response generation: {e}")
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error("Max retries reached. Returning error message.")
                    return JsonResponse(
                        {"response": "Sorry, there was an error processing your request. Please try again later."}
                    )

    return JsonResponse({"response": "Invalid request method."})


from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.csrf import csrf_exempt

@login_required
def like_post(request, pk):
    post = get_object_or_404(Post, pk=pk)
    post.likes += 1
    post.save()
    return JsonResponse({'likes': post.likes})


@login_required
def dislike_post(request, pk):
    post = get_object_or_404(Post, pk=pk)
    post.dislikes += 1
    post.save()
    return JsonResponse({'dislikes': post.dislikes})



from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import Reply, Post
from .models import TeacherProfileDetails, StudentProfileDetails  # Import profile models
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def add_reply(request):
    if request.method == 'POST':
        post_id = request.POST.get('id')
        reply_content = request.POST.get('reply_content')

        if not post_id or not reply_content:
            return JsonResponse({'error': 'Invalid data'}, status=400)

        try:
            post = Post.objects.get(id=post_id)
            reply = Reply.objects.create(
                post=post,
                content=reply_content,
                author=request.user,
                role='student' if hasattr(request.user, 'student_profile') else 'teacher',
            )
            reply_data = {
                'author': reply.author.username,
                'role': reply.role,
                'content': reply.content,
                'date_posted': reply.date_posted.strftime('%B %d, %Y, %I:%M %p'),
                'author_image': reply.author.student_profile.image if reply.role == 'student' else reply.author.teacher_profile.image,
            }
            return JsonResponse({'reply': reply_data})
        except Post.DoesNotExist:
            return JsonResponse({'error': 'Post not found'}, status=404)
    return JsonResponse({'error': 'Invalid request'}, status=400)



from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

@login_required
@csrf_exempt  # Required only if you aren't sending CSRF tokens (fetch already includes it here)
def like_post(request):
    if request.method == 'POST':
        try:
            # Parse JSON data
            data = json.loads(request.body)
            post_id = data.get('id')  # Extract `id` from JSON body
            post = get_object_or_404(Post, id=post_id)

            # Check if the user already liked the post
            if request.user in post.liked_by.all():
                return JsonResponse({'error': 'You have already liked this post.'}, status=400)
            
            # Remove dislike if it exists
            if request.user in post.disliked_by.all():
                post.disliked_by.remove(request.user)
                post.dislikes -= 1
            
            # Add like
            post.liked_by.add(request.user)
            post.likes += 1
            post.save()

            return JsonResponse({'likes': post.likes, 'dislikes': post.dislikes})
        except (KeyError, json.JSONDecodeError) as e:
            return JsonResponse({'error': 'Invalid request data.'}, status=400)

@login_required
@csrf_exempt
def dislike_post(request):
    if request.method == 'POST':
        try:
            # Parse JSON data
            data = json.loads(request.body)
            post_id = data.get('id')  # Extract `id` from JSON body
            post = get_object_or_404(Post, id=post_id)

            # Check if the user already disliked the post
            if request.user in post.disliked_by.all():
                return JsonResponse({'error': 'You have already disliked this post.'}, status=400)
            
            # Remove like if it exists
            if request.user in post.liked_by.all():
                post.liked_by.remove(request.user)
                post.likes -= 1
            
            # Add dislike
            post.disliked_by.add(request.user)
            post.dislikes += 1
            post.save()

            return JsonResponse({'likes': post.likes, 'dislikes': post.dislikes})
        except (KeyError, json.JSONDecodeError) as e:
            return JsonResponse({'error': 'Invalid request data.'}, status=400)





from django.shortcuts import render, redirect, get_object_or_404
from .models import Message
from django.contrib.auth.decorators import login_required
@login_required
def message_list(request):
    # Retrieve messages where the user is either the sender or the receiver
    messages = Message.objects.filter(
        receiver_author=request.user
    ) | Message.objects.filter(
        sender_author=request.user
    )
    # Remove duplicates if the user sends a message to themselves
    messages = messages.distinct().order_by('-date')

    # Pass profile information to the template
    message_profiles = []
    for message in messages:
        if hasattr(message.sender_author, 'student_profile'):
            sender_profile_pic = message.sender_author.student_profile.image
        elif hasattr(message.sender_author, 'teacher_profile'):
            sender_profile_pic = message.sender_author.teacher_profile.image
        else:
            sender_profile_pic = 'https://i.imgur.com/7suwDp5.jpeg'

        if hasattr(message.receiver_author, 'student_profile'):
            receiver_profile_pic = message.receiver_author.student_profile.image
        elif hasattr(message.receiver_author, 'teacher_profile'):
            receiver_profile_pic = message.receiver_author.teacher_profile.image
        else:
            receiver_profile_pic = 'https://i.imgur.com/7suwDp5.jpeg'

        message_profiles.append({
            'message': message,
            'sender_profile_pic': sender_profile_pic,
            'receiver_profile_pic': receiver_profile_pic,
        })

    return render(request, 'blog/msglist.html', {'message_profiles': message_profiles, 'current_user': request.user})


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from blog.models import Message
from django.http import HttpResponse

@login_required
def send_message(request):
    if request.method == 'POST':
        subject = request.POST['subject']
        content = request.POST['content']
        receiver_email = request.POST['receiver_email']

        # Validate receiver email
        try:
            receiver = User.objects.get(email=receiver_email)
        except User.DoesNotExist:
            return HttpResponse("The email address provided does not belong to a registered user.", status=400)

        # Determine roles and roll number
        sender_role = 'student' if hasattr(request.user, 'student_profile') else request.user.teacher_profile.role
        receiver_role = 'student' if hasattr(receiver, 'student_profile') else receiver.teacher_profile.role

       

        # Create and save the message
        message = Message.objects.create(
            sender_author=request.user,
            receiver_author=receiver,
            sender_email=request.user.email,
            receiver_email=receiver_email,
            sender_role=sender_role,
            receiver_role=receiver_role,
            subject=subject,
            content=content,
            
        )
        message.save()

        return redirect('message_list')
    
    return render(request, 'blog/msgsend.html')


@login_required
def message_detail(request):
    message_id = request.POST['id']
    message = get_object_or_404(Message, id=message_id)

    # Update statuses based on the current user's role
    if request.user == message.receiver_author and message.receiver_status != "read":
        message.receiver_status = "read"
        message.save()
    if request.user == message.sender_author and message.sender_status != "read":
        message.sender_status = "read"
        message.save()

    # Fetch sender and receiver profile pictures
    sender_profile_pic = None
    receiver_profile_pic = None

    if hasattr(message.sender_author, 'student_profile'):
     
        sender_profile_pic = message.sender_author.student_profile.image
        
    elif hasattr(message.sender_author, 'teacher_profile'):
   
        sender_profile_pic = message.sender_author.teacher_profile.image

    if hasattr(message.receiver_author, 'student_profile'):

        receiver_profile_pic = message.receiver_author.student_profile.image
    elif hasattr(message.receiver_author, 'teacher_profile'):

        receiver_profile_pic = message.receiver_author.teacher_profile.image

    return render(request, 'blog/msgdetail.html', {
        'message': message,
        'sender_profile_pic': sender_profile_pic,
        'receiver_profile_pic': receiver_profile_pic,
    })



from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.utils.timezone import now, timedelta
from django.http import JsonResponse
from .models import EmergencyMessage, StudentProfileDetails, TeacherProfileDetails
from .forms import EmergencyMessageForm

@login_required
def send_emergency_message(request):
    user = request.user

    # Fetch user's profile
    try:
        profile = StudentProfileDetails.objects.get(email=user.email)
    except StudentProfileDetails.DoesNotExist:
        try:
            profile = TeacherProfileDetails.objects.get(email=user.email)
        except TeacherProfileDetails.DoesNotExist:
            return render(request, "blog/msg.html", {"message": "Please update your profile before sending an emergency message."})

    if request.method == "POST":
        problem = request.POST.get('problem')
        sender_role = profile.role
        sender_department = profile.department
        sender_phone_number = profile.phone_number
        sender_roll_number = profile.roll_number

        # Create EmergencyMessage object
        emergency_message = EmergencyMessage.objects.create(
            problem=problem,
            sender=user,
            sender_role=sender_role,
            sender_roll_number=sender_roll_number,
            sender_department=sender_department,
            sender_phone_number=sender_phone_number,
            sent_to_role="doctor",
        )

        # Assign message to all doctors in the same department
        doctors = User.objects.filter(teacher_profile__role="doctor", teacher_profile__department=sender_department)
        emergency_message.sent_to_user.add(*doctors)
        emergency_message.save()

        return redirect("emergency_list")

    return render(request, "blog/send_emergency_message.html")


def msg_called(request):
    now_time = now()
    five_minutes_ago = now_time - timedelta(minutes=5)

    # Get unresolved messages
    unresolved_messages = EmergencyMessage.objects.filter(
        sent_time__lte=now_time, status="pending"
    )

    escalated_count = 0

    for message in unresolved_messages:
        if message.sent_time <= five_minutes_ago and message.sent_to_role == "doctor":
            # Escalate to all teachers in the department
            teachers = User.objects.filter(teacher_profile__role="teacher", teacher_profile__department=message.sender_department)
            message.sent_to_user.add(*teachers)
            message.sent_to_role = "teacher"
            message.save()
            escalated_count += 1

    return JsonResponse({"message": f"{escalated_count} messages escalated to teachers."})






from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from .models import EmergencyMessage, StudentProfileDetails, TeacherProfileDetails

from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import StudentProfileDetails, TeacherProfileDetails, EmergencyMessage
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from .models import EmergencyMessage, StudentProfileDetails, TeacherProfileDetails

@login_required
def emergency_list(request):
    user = request.user
    # Fetch user's profile
    try:
        profile = StudentProfileDetails.objects.get(email=user.email)
    except StudentProfileDetails.DoesNotExist:
        try:
            profile = TeacherProfileDetails.objects.get(email=user.email)
        except TeacherProfileDetails.DoesNotExist:
            return render(request, "blog/msg.html", {"message": "Profile not found."})

    role = profile.role
    print(role)

    if role=="doctor" or role == "teacher":
        # Doctors and teachers see actionable messages in their department
        # Include messages from students and other teachers (exclude their own messages)
        messages = EmergencyMessage.objects.filter(
            sender_department=profile.department,
            status="pending",
        ).exclude(sender=user).select_related('sender')
        '''messages = EmergencyMessage.objects.filter(
            sender_department=profile.department,
            status="pending",
        ).exclude(sender=user).select_related('sender')'''
        can_resolve = True  # Doctors and teachers can resolve
        print("hello")
        if messages.count() == 0:
            messages = EmergencyMessage.objects.filter(sender=user).select_related('sender')
        
    else:
        # Students see their own messages
        messages = EmergencyMessage.objects.filter(sender=user).select_related('sender')
        can_resolve = False  # Students cannot resolve

    # Add sender details (e.g., role number)
    for message in messages:
        sender_profile = None
        if message.sender_role == "student":
            sender_profile = StudentProfileDetails.objects.filter(user=message.sender).first()
        elif message.sender_role in ["teacher", "doctor"]:
            sender_profile = TeacherProfileDetails.objects.filter(user=message.sender).first()

        if sender_profile:
            message.sender.roll_number = sender_profile.roll_number

    # Order messages by the most recent `sent_time`
    messages = messages.order_by('-sent_time')
    

    return render(request, "blog/emergency_list.html", {"messages": messages, "can_resolve": can_resolve,"userb":user.username})





from django.shortcuts import render

@login_required
def resolve_message(request):
    message_id=request.POST['id']
    message = get_object_or_404(EmergencyMessage, id=message_id)
    print(message)
    if request.method == "POST":
        resolution_status = request.POST.get("action")  # 'accept' or 'reject'
        reply = request.POST.get("reply")

        if message.status == "pending":
            message.status = "accepted" if resolution_status == "accept" else "rejected"
            message.reply = reply
            message.resolved_by = request.user
            message.resolved_time = now()
            message.save()
            return redirect("emergency_list")  # Redirect to the emergency list after saving

    # Render the response page to enter reply and take action
    return render(request, "blog/resolve_message.html", {"message": message})

@login_required
def resolve_msg(request):
    message_id=request.POST['id']
    message = get_object_or_404(EmergencyMessage, id=message_id)
    return render(request, "blog/resolve_message.html", {"message": message})


@login_required
def emergency_history(request, user_id):
    # Fetch the user whose history is being viewed
    target_user = get_object_or_404(User, id=user_id)

    # Only allow the logged-in user to view their own history or staff to view others
    if request.user != target_user and not request.user.is_staff:
        return render(request, "error.html", {"message": "You do not have permission to view this history."})

    # Fetch all emergency messages sent by the target user
    messages = EmergencyMessage.objects.filter(sender=target_user).order_by('-sent_time')

    # Render the history page
    return render(request, "emergency_history.html", {"messages": messages, "user": target_user})


from django.shortcuts import render
from .models import Post, StudentProfileDetails, TeacherProfileDetails


from django.core.exceptions import ObjectDoesNotExist

@login_required
def search(request):
    query = request.POST.get('query', '').strip()
    user = request.user

    # Initialize context
    context = {'query': query, 'query_class': 'query-highlight'}

    try:
        if hasattr(user, 'teacher_profile') and user.teacher_profile.role in ['teacher', 'doctor']:
            # If current user is a teacher or doctor
            if 'emergency' in request.META.get('HTTP_REFERER', ''):  # Emergency-related search

                # Get student and teacher profiles matching the query
                student_profiles = StudentProfileDetails.objects.filter(
                    roll_number__icontains=query
                ) | StudentProfileDetails.objects.filter(
                    user__username__icontains=query
                )

                teacher_profiles = TeacherProfileDetails.objects.filter(
                    roll_number__icontains=query
                ) | TeacherProfileDetails.objects.filter(
                    user__username__icontains=query
                )

                # Prepare data for each profile
                profile_data = []
                for profile in student_profiles:
                    emergency_messages = EmergencyMessage.objects.filter(sender=profile.user)
                    accept_count = emergency_messages.filter(status='accepted').count()
                    reject_count = emergency_messages.filter(status='rejected').count()
                    pending_count = emergency_messages.filter(status='pending').count()

                    profile_data.append({
                        'type': 'student',
                        'profile': profile,
                        'accept_count': accept_count,
                        'reject_count': reject_count,
                        'pending_count': pending_count,
                    })

                for profile in teacher_profiles:
                    emergency_messages = EmergencyMessage.objects.filter(sender=profile.user)
                    accept_count = emergency_messages.filter(status='accepted').count()
                    reject_count = emergency_messages.filter(status='rejected').count()
                    pending_count = emergency_messages.filter(status='pending').count()

                    profile_data.append({
                        'type': 'teacher',
                        'profile': profile,
                        'accept_count': accept_count,
                        'reject_count': reject_count,
                        'pending_count': pending_count,
                    })

                context['profile_data'] = profile_data
                return render(request, 'blog/search_results.html', context)

            else:
                # For non-emergency searches, display posts
                posts = Post.objects.filter(title__icontains=query) | Post.objects.filter(content__icontains=query)
                context['posts'] = posts
                return render(request, 'blog/post.html', context)

        elif hasattr(user, 'student_profile') and user.student_profile.role == 'student':
            # If current user is a student, search for posts only
            posts = Post.objects.filter(title__icontains=query) | Post.objects.filter(content__icontains=query)
            context['posts'] = posts
            return render(request, 'blog/post.html', context)

    except ObjectDoesNotExist:
        context['error_message'] = "Profile not found for the user."
        return render(request, 'blog/search_results.html', context)

    # Default error message if no results found
    context['error_message'] = "No matching results found."
    return render(request, 'blog/search_results.html', context)


from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Message, EmergencyMessage

@login_required
def get_notification_count(request):
    user = request.user

    # Count unread messages where the user is the receiver
    unread_direct_messages = Message.objects.filter(receiver_author=user, receiver_status="unread").count()

    # Count pending emergency messages sent to the current user
    unread_emergency_messages = EmergencyMessage.objects.filter(
        sent_to_user=user, status="pending"
    ).count()

    # Total count
    total_unread_count = unread_direct_messages + unread_emergency_messages

    return JsonResponse({"total_count": total_unread_count})


import google.generativeai as genai
from django.contrib.auth.models import User
from django.utils.timezone import now
from django.http import JsonResponse
from .models import Post
import random

# Configure Gemini API


def generate_health_post():
    genai.configure(api_key="AIzaSyC5GHHDoBNE7oaSFGD7WXkE5RBkNHG7AXQ")
    model = genai.GenerativeModel("gemini-1.5-flash")
    """
    Generates a unique and informative health-related blog post.
    - Title should be catchy and engaging without a date.
    - Content should be a single 4-line paragraph with useful health tips, facts, or awareness.
    """

    prompt = """
    Create a compelling health-related blog post.
    - Generate an eye-catching title that does not contain the date.
    - Write an engaging 4-line paragraph with health facts, awareness, or useful tips.
    - Ensure it is informative, positive, and practical for readers.
    - Avoid duplicate content and keep it unique.
    -based on day to today activites and changes and updatation or scam and imporvenments or celebration on health info.
    -if sometime currnt day is anything spectal can give on that info .which good and helpful people according health
    
    Format:
    Title: [Catchy Title]
    Content: [4-line paragraph]
    """

    response = model.generate_content(prompt)
    
    if response and response.text:
        return response.text.strip()
    else:
        return None


# Django view function for AI post creation
def ai_create_post(request):
    try:
        # Retrieve AI bot user
        ai_bot_user = User.objects.get(username="healthbot")
    except User.DoesNotExist:
        return JsonResponse({"error": "AI Bot user does not exist."}, status=400)

    # Generate a new post
    content = generate_health_post()
    
    if not content:
        return JsonResponse({"error": "AI-generated content is empty."}, status=400)

    # Extract the first line as title and the rest as content
    lines = content.split("\n")
    title = lines[0].replace("Title: ", "").strip() if lines else "Health Awareness Insights"
    body_content = "\n".join(lines[1:]).replace("Content: ", "").strip()

    # Ensure the post is unique
    if Post.objects.filter(title=title).exists() or Post.objects.filter(content=body_content).exists():
        return return ai_create_post(request)

    # Save post
    post = Post(title=title, content=body_content, author=ai_bot_user, date_posted=now(), role='bot')
    post.save()

    return JsonResponse({"message": f"AI-generated post '{title}' saved successfully!"}, status=201)
