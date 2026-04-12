from django.dispatch import receiver
from django.urls import resolve, reverse
from django.utils.translation import gettext_lazy as _

from pretix.control.signals import nav_event_settings
from pretix.presale.signals import checkout_flow_steps


@receiver(checkout_flow_steps, dispatch_uid='nss_profile_checkout_step')
def add_nss_profile_step(sender, **kwargs):
    from .checkoutflow import NssProfileStep
    return NssProfileStep


@receiver(nav_event_settings, dispatch_uid='nss_profile_nav')
def navbar_info(sender, request, **kwargs):
    url = resolve(request.path_info)
    if not request.user.has_event_permission(
        request.organizer, request.event,
        'event.settings.general:write', request=request,
    ):
        return []
    return [{
        'label': _('NSS Profile'),
        'url': reverse('plugins:pretix_nss_profile:settings', kwargs={
            'event': request.event.slug,
            'organizer': request.event.organizer.slug,
        }),
        'active': url.namespace == 'plugins:pretix_nss_profile',
    }]
