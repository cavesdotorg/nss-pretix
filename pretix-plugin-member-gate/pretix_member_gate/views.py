from django import forms
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from pretix.base.forms import SettingsForm
from pretix.base.models import Event
from pretix.control.views.event import EventSettingsFormView, EventSettingsViewMixin


class MemberGateSettingsForm(SettingsForm):
    member_gate_item_ids = forms.MultipleChoiceField(
        label=_("Member-only products"),
        help_text=_("Customers must be logged in to purchase any of these products (regardless of variation)."),
        widget=forms.CheckboxSelectMultiple,
        required=False,
    )
    member_gate_variation_ids = forms.MultipleChoiceField(
        label=_("Member-price variations"),
        help_text=_("Customers must be logged in to add any of these specific variations to their cart."),
        widget=forms.CheckboxSelectMultiple,
        required=False,
    )
    member_gate_required_provider = forms.ChoiceField(
        label=_("Required login provider"),
        help_text=_(
            "Require login via a specific SSO provider. "
            "Leave blank to allow any logged-in customer."
        ),
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

        item_choices = []
        variation_choices = []
        for item in event.items.prefetch_related('variations').order_by('name'):
            item_choices.append((str(item.pk), str(item.name)))
            for variation in item.variations.all():
                variation_choices.append((str(variation.pk), f'{item.name} – {variation.value}'))
        self.fields['member_gate_item_ids'].choices = item_choices
        self.fields['member_gate_variation_ids'].choices = variation_choices

        provider_choices = [('', _('— any provider —'))]
        for p in event.organizer.sso_providers.filter(is_active=True).order_by('name'):
            provider_choices.append((str(p.pk), p.name))
        self.fields['member_gate_required_provider'].choices = provider_choices


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
