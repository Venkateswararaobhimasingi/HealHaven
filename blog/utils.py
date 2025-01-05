import os

def handle_uploaded_file(uploaded_file):
    profile_pics_path = os.path.join(settings.MEDIA_ROOT, 'profile_pics')
    os.makedirs(profile_pics_path, exist_ok=True)
    file_path = os.path.join(profile_pics_path, uploaded_file.name)
    with open(file_path, 'wb') as destination:
        for chunk in uploaded_file.chunks():
            destination.write(chunk)
    return file_path
