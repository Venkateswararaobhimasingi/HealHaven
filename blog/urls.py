from django.urls import path
from . import views

urlpatterns = [
    #path("#", admin.site.urls),
    path("",views.post,name='home'),
    path("msgbro/",views.msg,name='msg'),
    path("base/",views.base,name='base'),
    path("about/",views.about,name='about'),
    path("login/",views.login,name='login'),
    path("register/",views.register,name='register'),
    path("forgotpassword/",views.forgotpassword,name='forgotpassword'),
    path("register_student/",views.register_student,name='register_student'),
    path("register_teacher/",views.register_teacher,name='register_teacher'),
    path("student_login/",views.student_login,name='student_login'),
    path("teacher_login/",views.teacher_login,name='teacher_login'),
    path('logout/', views.user_logout, name='logout'),
    path('msgcalled/', views.msgcalled, name='msgcalled'),
    path('langu/',views.langu,name='langu'),
    path('send_otp/', views.send_otp, name='send_otp'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('reset_password/', views.reset_password, name='reset_password'),
    path('student_profile/', views.student_profile_view, name='student_profile'),
    path('teacher_profile/', views.teacher_profile_view, name='teacher_profile'),
    path('update_student_profile/', views.update_student_profile_view, name='update_student_profile'),
    path('update_teacher_profile/', views.update_teacher_profile_view, name='update_teacher_profile'),
    path('post/', views.post, name='post'),
     path('myposts/', views.myposts, name='myposts'),
    path('post_update/', views.post_update, name='post_update'),
    path('post/new/', views.create_post, name='create_post'),
    path('post_detail', views.post_detail, name='post_detail'),
    path('post_delete/', views.post_delete, name='post_delete'),
    path('post_delete_view/', views.post_delete_view, name='post_delete_view'),
    
    path('chat/', views.chat, name='chat'),
    path("chatbot", views.chatbot_response, name="chatbot"),
    path('like/', views.like_post, name='like_post'),
    path('dislike/', views.dislike_post, name='dislike_post'),
    path('reply/', views.add_reply, name='add_reply'),


    path('list/', views.message_list, name='message_list'),
    path('send/', views.send_message, name='send_message'),
    path('msg/', views.message_detail, name='message_detail'),

    path('emergency_send/', views.send_emergency_message, name='send_emergency_message'),
    path('emergency_list/', views.emergency_list, name='emergency_list'),
    path('emergency/', views.resolve_message, name='resolve_message'),
    path('emergencymsg/', views.resolve_msg, name='resolve_msg'),
    path('emergency_history/<int:user_id>/', views.emergency_history, name='emergency_history'),
    path('msg_called/', views.msg_called, name='msg_called'),

    path('search/', views.search, name='search'),
    path('notification-count/', views.get_notification_count, name='notification_count'),
    path('ai_create_post/',views.ai_create_post,name='ai_create_post'),

]