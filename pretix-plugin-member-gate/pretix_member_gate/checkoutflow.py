from urllib.parse import quote

from django.http import HttpResponseRedirect
from django.urls import reverse

from pretix.presale.checkoutflow import BaseCheckoutFlowStep
from pretix.presale.views import get_cart


class MemberGateStep(BaseCheckoutFlowStep):
    identifier = 'member_gate'
    # 48 — runs after CustomerStep (45) so the normal login flow handles
    # most cases; we catch anything that slips through (e.g. customer
    # accounts disabled but plugin still active).
    priority = 48

    def is_applicable(self, request):
        variation_id = request.event.settings.get('member_gate_variation_id')
        if not variation_id:
            return False
        return get_cart(request).filter(variation_id=variation_id).exists()

    def is_completed(self, request, warn=False):
        return bool(request.customer)

    def get(self, request):
        self.request = request
        if self.is_completed(request):
            return HttpResponseRedirect(self.get_next_url(request))

        # Fall back to forcing login if somehow reached without a customer session.
        login_url = (
            request.event.settings.get('member_gate_login_url') or
            reverse(
                'presale:organizer.customer.login',
                kwargs={'organizer': request.organizer.slug},
            )
        )
        next_url = reverse(
            'presale:event.checkout.start',
            kwargs={
                'organizer': request.organizer.slug,
                'event': request.event.slug,
            },
        )
        return HttpResponseRedirect(f'{login_url}?next={quote(next_url)}')

    def post(self, request):
        self.request = request
        return HttpResponseRedirect(self.get_next_url(request))
