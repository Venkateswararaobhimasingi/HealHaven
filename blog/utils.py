# your_app/utils.py
import os

def handle_uploaded_file(uploaded_file):
    temp_file_path = os.path.join('/tmp', uploaded_file.name)
    with open(temp_file_path, 'wb') as temp_file:
        for chunk in uploaded_file.chunks():
            temp_file.write(chunk)
    return temp_file_path
