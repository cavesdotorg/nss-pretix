from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class MemberGateApp(AppConfig):
    name = 'pretix_member_gate'
    verbose_name = _("Member-only ticket pricing")

    class PretixPluginMeta:
        name = _("Member-only ticket pricing")
        author = "NSS"
        version = "1.0.0"
        category = "RESTRICTION"
        description = _(
            "Requires customers to be logged in to purchase designated "
            "member-priced ticket variations. Works with any configured "
            "SSO provider or email/password login."
        )

    def ready(self):
        from . import signals  # NOQA
