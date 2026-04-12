from django.urls import path

from . import views

urlpatterns = [
    path(
        'control/event/<str:organizer>/<str:event>/nss-profile/',
        views.NssProfileSettings.as_view(),
        name='settings',
    ),
]
