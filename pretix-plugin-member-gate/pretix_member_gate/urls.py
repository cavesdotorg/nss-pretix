from django.urls import path

from . import views

urlpatterns = [
    path(
        'control/event/<str:organizer>/<str:event>/member-gate/',
        views.MemberGateSettings.as_view(),
        name='settings',
    ),
]
