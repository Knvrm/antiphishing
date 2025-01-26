from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required

@login_required(login_url="/accounts/google/login/")
def home(request):
    return render(request, 'dashboard.html')