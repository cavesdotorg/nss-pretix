import logging
import os

from django.dispatch import receiver
from django.urls import resolve, reverse
from django.utils.translation import gettext_lazy as _

from pretix.control.signals import nav_event_settings
from pretix.presale.signals import checkout_flow_steps

log = logging.getLogger(__name__)


@receiver(checkout_flow_steps, dispatch_uid='nss_profile_checkout_step')
def add_nss_profile_step(sender, **kwargs):
    from .checkoutflow import NssProfileStep
    return NssProfileStep



def provision_ym_sso_provider(sender, instance, created, **kwargs):
    """Auto-create the YM SSO provider for any new organizer."""
    if not created:
        return

    base_url = os.environ.get('YM_SSO_BASE_URL', '').strip()
    client_id = os.environ.get('YM_SSO_CLIENT_ID', '').strip()
    client_secret = os.environ.get('YM_SSO_CLIENT_SECRET', '').strip()

    if not (base_url and client_id and client_secret):
        log.info(
            'YM_SSO_BASE_URL / YM_SSO_CLIENT_ID / YM_SSO_CLIENT_SECRET not set; '
            'skipping auto-provisioning SSO provider for organizer %s', instance.slug
        )
        return

    from pretix.base.customersso.oidc import oidc_validate_and_complete_config
    from pretix.base.models.customers import CustomerSSOProvider

    if instance.sso_providers.filter(configuration__base_url=base_url).exists():
        log.info('YM SSO provider already exists for organizer %s', instance.slug)
        return

    config = {
        'base_url': base_url,
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'openid email profile',
        'uid_field': 'sub',
        'email_field': 'email',
    }
    try:
        oidc_validate_and_complete_config(config)
    except Exception as exc:
        log.error('Failed to validate YM OIDC config for organizer %s: %s', instance.slug, exc)
        return

    CustomerSSOProvider.objects.create(
        organizer=instance,
        name='YourMembership (NSS)',
        button_label='Log in with NSS membership',
        method=CustomerSSOProvider.METHOD_OIDC,
        is_active=True,
        configuration=config,
    )
    log.info('Created YM SSO provider for organizer %s', instance.slug)


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
