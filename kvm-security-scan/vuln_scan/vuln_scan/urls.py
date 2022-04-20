from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    url('visual/', include('visual.urls')),
    url(r'^admin/', admin.site.urls),
]
