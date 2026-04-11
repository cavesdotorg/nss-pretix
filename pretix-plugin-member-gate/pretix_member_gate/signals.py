from django.dispatch import receiver
from django.urls import resolve, reverse
from django.utils.translation import gettext_lazy as _

from pretix.control.signals import nav_event_settings
from pretix.presale.signals import checkout_flow_steps


@receiver(checkout_flow_steps, dispatch_uid='member_gate_checkout_step')
def add_member_gate_step(sender, **kwargs):
    from .checkoutflow import MemberGateStep
    return MemberGateStep


@receiver(nav_event_settings, dispatch_uid='member_gate_nav')
def navbar_info(sender, request, **kwargs):
    url = resolve(request.path_info)
    if not request.user.has_event_permission(
        request.organizer, request.event,
        'event.settings.general:write', request=request,
    ):
        return []
    return [{
        'label': _('Member Gate'),
        'url': reverse('plugins:pretix_member_gate:settings', kwargs={
            'event': request.event.slug,
            'organizer': request.event.organizer.slug,
        }),
        'active': url.namespace == 'plugins:pretix_member_gate',
    }]
