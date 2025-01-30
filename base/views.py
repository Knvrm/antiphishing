from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .gmail_integration import MailService

def inbox_view(request):
    mail_service = MailService()
    all_emails = mail_service.get_emails()
    emails = all_emails[:5]
    return render(request, 'inbox.html', {'emails': emails})

@login_required(login_url="/accounts/google/login/")
def home(request):
    return render(request, 'inbox.html')