from django import forms
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from pretix.base.forms import SettingsForm
from pretix.base.models import Event
from pretix.control.views.event import EventSettingsFormView, EventSettingsViewMixin


class NssProfileSettingsForm(SettingsForm):
    nss_profile_enabled = forms.BooleanField(
        label=_("Enable NSS profile step"),
        help_text=_(
            "When enabled, logged-in members will be shown a profile form "
            "during checkout. Their YM profile data will be pre-filled and "
            "saved as order question answers."
        ),
        required=False,
    )
    nss_profile_provider_id = forms.ChoiceField(
        label=_("Required SSO provider"),
        help_text=_(
            "Only show the profile step to customers who logged in via this "
            "provider. Leave blank to show for any logged-in customer."
        ),
        required=False,
    )

    def __init__(self, *args, **kwargs):
        event = kwargs.pop('event')
        super().__init__(*args, **kwargs)
        provider_choices = [('', _('— any provider —'))]
        for p in event.organizer.sso_providers.filter(is_active=True).order_by('name'):
            provider_choices.append((str(p.pk), p.name))
        self.fields['nss_profile_provider_id'].choices = provider_choices


class NssProfileSettings(EventSettingsViewMixin, EventSettingsFormView):
    model = Event
    form_class = NssProfileSettingsForm
    template_name = 'pretix_nss_profile/settings.html'
    permission = 'event.settings.general:write'

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['event'] = self.request.event
        return kwargs

    def get_success_url(self):
        return reverse('plugins:pretix_nss_profile:settings', kwargs={
            'organizer': self.request.event.organizer.slug,
            'event': self.request.event.slug,
        })
