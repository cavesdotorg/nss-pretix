import json
import logging

import redis as redis_lib
from django import forms
from django.http import HttpResponseRedirect
from django.utils.translation import gettext_lazy as _

from pretix.base.models import Question, QuestionAnswer
from pretix.presale.checkoutflow import TemplateFlowStep
from pretix.presale.views import CartMixin, get_cart

log = logging.getLogger(__name__)

_REDIS_URL = "redis://valkey:6379/3"
_redis_conn = None


def _get_redis():
    global _redis_conn
    if _redis_conn is None:
        _redis_conn = redis_lib.Redis.from_url(_REDIS_URL, decode_responses=True)
    return _redis_conn


def _get_ym_profile(member_id: str) -> dict | None:
    try:
        raw = _get_redis().get(f"ym_profile:{member_id}")
        return json.loads(raw) if raw else None
    except Exception as exc:
        log.warning("Failed to fetch YM profile from Redis for member %s: %s", member_id, exc)
        return None


# (identifier, label, user-editable)
_QUESTION_DEFS = [
    ("nss_number",     _("NSS Member Number"),      False),
    ("nss_name",       _("Name"),                   True),
    ("nss_grotto",     _("Grotto Affiliation"),      True),
    ("nss_expiration", _("Membership Expiration"),   False),
    ("nss_address",    _("Home Address"),            True),
]
_READONLY_FIELDS = {ident for ident, _, editable in _QUESTION_DEFS if not editable}


def _ensure_questions(event) -> dict:
    """
    Return a mapping of identifier → Question, creating any that are missing.
    """
    questions = {}
    for pos, (identifier, label, _) in enumerate(_QUESTION_DEFS):
        q, _ = Question.objects.get_or_create(
            event=event,
            identifier=identifier,
            defaults={
                "question": str(label),
                "type": Question.TYPE_STRING,
                "required": False,
                "position": 200 + pos,
            },
        )
        questions[identifier] = q
    return questions


class NssProfileForm(forms.Form):
    nss_number     = forms.CharField(label=_("NSS Member Number"),     required=False)
    nss_name       = forms.CharField(label=_("Name"),                  required=True)
    nss_grotto     = forms.CharField(label=_("Grotto Affiliation"),    required=False)
    nss_expiration = forms.CharField(label=_("Membership Expiration"), required=False)
    nss_address    = forms.CharField(
        label=_("Home Address"),
        required=False,
        widget=forms.Textarea(attrs={"rows": 3}),
    )

    def __init__(self, *args, **kwargs):
        profile = kwargs.pop("profile", {})
        # Pre-populate initial values from YM profile
        initial = kwargs.pop("initial", {})
        for ident, _, _ in _QUESTION_DEFS:
            initial.setdefault(ident, profile.get(ident, ""))
        kwargs["initial"] = initial
        super().__init__(*args, **kwargs)
        # Read-only fields cannot be edited by the user
        for ident in _READONLY_FIELDS:
            self.fields[ident].disabled = True


class NssProfileStep(CartMixin, TemplateFlowStep):
    identifier = "nss_profile"
    priority = 55  # after CustomerStep (45) and MemberGateStep (48)
    template_name = "pretix_nss_profile/checkout.html"
    label = _("Member Profile")
    icon = "user"

    def is_applicable(self, request):
        if not request.event.settings.get("nss_profile_enabled", as_type=bool):
            return False
        if not request.customer:
            return False
        required_provider = request.event.settings.get("nss_profile_provider_id")
        if required_provider and str(request.customer.provider_id) != str(required_provider):
            return False
        member_id = getattr(request.customer, "external_identifier", None)
        if not member_id:
            return False
        return _get_ym_profile(str(member_id)) is not None

    def is_completed(self, request, warn=False):
        question_ids = request.event.settings.get("nss_profile_question_ids", as_type=list) or []
        if not question_ids:
            return False
        cart_qs = get_cart(request)
        if not cart_qs.exists():
            return True
        return QuestionAnswer.objects.filter(
            cartposition__in=cart_qs,
            question_id__in=question_ids,
        ).exists()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["cart"] = self.get_cart()
        return ctx

    def get(self, request):
        self.request = request
        if self.is_completed(request):
            return HttpResponseRedirect(self.get_next_url(request))
        member_id = str(request.customer.external_identifier)
        profile = _get_ym_profile(member_id) or {}
        return self.render(form=NssProfileForm(profile=profile))

    def post(self, request):
        self.request = request
        member_id = str(request.customer.external_identifier)
        profile = _get_ym_profile(member_id) or {}
        form = NssProfileForm(data=request.POST, profile=profile)

        if not form.is_valid():
            return self.render(form=form)

        questions = _ensure_questions(request.event)

        # Persist question PKs so is_completed can look them up
        request.event.settings.set(
            "nss_profile_question_ids",
            [str(q.pk) for q in questions.values()],
        )

        cart_qs = get_cart(request)
        for cp in cart_qs:
            for ident, _, editable in _QUESTION_DEFS:
                if editable:
                    value = form.cleaned_data.get(ident, "")
                else:
                    # Disabled fields are not submitted; use cached profile value
                    value = profile.get(ident, "")
                QuestionAnswer.objects.update_or_create(
                    cartposition=cp,
                    question=questions[ident],
                    defaults={"answer": value},
                )

        return HttpResponseRedirect(self.get_next_url(request))
