from django.contrib import admin
from django.urls import path, include
from base import views
from .views import index_redirect

urlpatterns = [
    path('admin/', include('admin_honeypot.urls')),
    path('panel/manager/', admin.site.urls),
    path('', index_redirect),
    path('dashboard/', views.home, name='dashboard'),
    path('inbox/', views.inbox_view, name='inbox'),
    path('accounts/', include('allauth.urls'))
]
