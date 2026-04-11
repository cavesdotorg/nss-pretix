from django import forms
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from pretix.base.forms import SettingsForm
from pretix.base.models import Event
from pretix.control.views.event import EventSettingsFormView, EventSettingsViewMixin


class MemberGateSettingsForm(SettingsForm):
    member_gate_variation_id = forms.ChoiceField(
        label=_("Member-price variation"),
        help_text=_("Customers must be logged in to add this variation to their cart."),
        required=False,
    )
    member_gate_login_url = forms.CharField(
        label=_("Login URL override"),
        help_text=_(
            "Leave blank to use the default Pretix customer login page. "
            "Set to a custom URL (e.g. /oidc/login) to use an external login flow."
        ),
        required=False,
    )

    def __init__(self, *args, **kwargs):
        event = kwargs.pop('event')
        super().__init__(*args, **kwargs)
        choices = [('', _('— not configured —'))]
        for item in event.items.prefetch_related('variations').order_by('name'):
            for variation in item.variations.all():
                choices.append((str(variation.pk), f'{item.name} – {variation.value}'))
        self.fields['member_gate_variation_id'].choices = choices


class MemberGateSettings(EventSettingsViewMixin, EventSettingsFormView):
    model = Event
    form_class = MemberGateSettingsForm
    template_name = 'pretix_member_gate/settings.html'
    permission = 'event.settings.general:write'

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['event'] = self.request.event
        return kwargs

    def get_success_url(self):
        return reverse('plugins:pretix_member_gate:settings', kwargs={
            'organizer': self.request.event.organizer.slug,
            'event': self.request.event.slug,
        })
