from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .gmail_integration import MailService
from django.contrib import messages

def inbox_view(request):
    mail_service = MailService()
    all_emails = mail_service.get_emails()
    dangerous_emails = []
    suspicious_emails = []

    for email_ in all_emails:
        mail_service.pass_data_for_analysis(email_)
        email_.classification.classify()
        if email_.classification.resultClassification == "Опасное":
            dangerous_emails.append(email_)
        if email_.classification.resultClassification == "Подозрительное":
            suspicious_emails.append(email_)

    if dangerous_emails:
        if len(dangerous_emails) > 1:
            messages.error(request, "Найдены опасные письма!")
        if len(dangerous_emails) == 1:
            messages.error(request, "Найдено опасное письмо!")

    if suspicious_emails:
        if len(suspicious_emails) > 1:
            messages.warning(request, "Найдены подозрительные письма!")
        if len(suspicious_emails) == 1:
            messages.warning(request, "Найдено подозрительное письмо!")

    return render(request, 'inbox.html', {'emails': all_emails})

@login_required(login_url="/accounts/google/login/")
def home(request):
    return render(request, 'inbox.html')