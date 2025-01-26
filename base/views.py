from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .gmail_integration import authenticate_gmail, list_messages

def inbox_view(request):
    service = authenticate_gmail()
    messages = list_messages(service)
    return render(request, 'inbox.html', {'messages': messages})

@login_required(login_url="/accounts/google/login/")
def home(request):
    return render(request, 'dashboard.html')