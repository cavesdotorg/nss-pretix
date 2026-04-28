from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class NssProfileApp(AppConfig):
    name = 'pretix_nss_profile'
    verbose_name = _("NSS Member Profile")

    class PretixPluginMeta:
        name = _("NSS Member Profile")
        author = "NSS"
        version = "1.0.0"
        category = "CUSTOMIZATION"
        description = _(
            "Pulls the logged-in member's YM profile during checkout, "
            "pre-fills a form with their name, NSS number, grotto, expiration, "
            "and address, and saves the confirmed data as order question answers."
        )

    def ready(self):
        from . import signals  # NOQA
        from django.db.models.signals import post_save
        from pretix.base.models import Organizer
        post_save.connect(
            signals.provision_ym_sso_provider,
            sender=Organizer,
            dispatch_uid='nss_profile_provision_ym_sso',
        )
