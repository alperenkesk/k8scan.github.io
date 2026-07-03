"""
Stripe payment routes.

POST /api/v1/payments/create-checkout – create Stripe Checkout session
POST /api/v1/payments/portal          – create Stripe Customer Portal session
POST /api/v1/payments/webhook         – Stripe webhook receiver
GET  /api/v1/payments/plans           – list available plans
"""
import json
from datetime import datetime, timezone

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from backend.auth import get_current_user
from backend.config import get_settings
from backend.database import get_db
from backend.models import Subscription, User

router   = APIRouter(prefix="/api/v1/payments", tags=["payments"])
settings = get_settings()


# ── Schemas ───────────────────────────────────────────────────────────────────

_ALLOWED_REDIRECT_HOSTS = {
    "localhost", "127.0.0.1",
    "k8scan.io", "www.k8scan.io", "app.k8scan.io",
}


def _validate_redirect_url(url: str) -> str:
    """Only allow redirects to known k8scan domains (prevents open redirect)."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must use http or https")
        if parsed.hostname not in _ALLOWED_REDIRECT_HOSTS:
            raise ValueError(f"Redirect to '{parsed.hostname}' is not allowed")
    except Exception as exc:
        raise ValueError(str(exc)) from exc
    return url


class CheckoutRequest(BaseModel):
    plan:          str   # "pro" | "enterprise"
    billing_cycle: str   # "monthly" | "annual"
    success_url:   str
    cancel_url:    str

    @field_validator("success_url", "cancel_url")
    @classmethod
    def safe_redirect_url(cls, v: str) -> str:
        return _validate_redirect_url(v)


PLAN_PRICES: dict[str, dict[str, str]] = {
    "pro": {
        "monthly": settings.STRIPE_PRICE_PRO_MONTHLY,
        "annual":  settings.STRIPE_PRICE_PRO_ANNUAL,
    },
    "enterprise": {
        "monthly": settings.STRIPE_PRICE_ENT_MONTHLY,
        "annual":  settings.STRIPE_PRICE_ENT_ANNUAL,
    },
}

PLAN_DISPLAY = {
    "starter":    {"name": "Starter",    "price_monthly": 9,  "scans": 3,       "features": ["3 scans/mo", "5 MB charts", "HTML report", "80+ checks", "PoC commands"]},
    "pro":        {"name": "Pro",         "price_monthly": 29, "scans": 10,      "features": ["10 scans/mo", "50 MB charts", "PoC commands", "5 team members", "Slack"]},
    "enterprise": {"name": "Enterprise", "price_monthly": 99, "scans": 999_999, "features": ["Unlimited scans", "Unlimited size", "SSO/SAML", "SLA support"]},
}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/plans")
async def list_plans():
    return PLAN_DISPLAY


@router.post("/create-checkout")
async def create_checkout(
    body: CheckoutRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Payment processing not configured.")

    import stripe  # lazy import – only needed when Stripe is configured
    stripe.api_key = settings.STRIPE_SECRET_KEY

    if body.plan not in PLAN_PRICES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid plan.")
    if body.billing_cycle not in ("monthly", "annual"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid billing cycle.")

    price_id = PLAN_PRICES[body.plan][body.billing_cycle]
    if not price_id:
        raise HTTPException(status_code=503, detail="Price not configured for this plan.")

    # Create or reuse Stripe customer
    if not current_user.stripe_customer_id:
        customer = stripe.Customer.create(
            email=current_user.email,
            name=current_user.full_name,
            metadata={"user_id": current_user.id},
        )
        current_user.stripe_customer_id = customer.id
        db.commit()

    session = stripe.checkout.Session.create(
        customer=current_user.stripe_customer_id,
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=body.success_url,
        cancel_url=body.cancel_url,
        metadata={"user_id": current_user.id, "plan": body.plan, "billing_cycle": body.billing_cycle},
    )
    return {"checkout_url": session.url}


@router.post("/portal")
async def customer_portal(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Payment processing not configured.")
    if not current_user.stripe_customer_id:
        raise HTTPException(status_code=400, detail="No active subscription found.")

    import stripe
    stripe.api_key = settings.STRIPE_SECRET_KEY

    origin = str(request.base_url).rstrip("/")
    session = stripe.billing_portal.Session.create(
        customer=current_user.stripe_customer_id,
        return_url=f"{origin}/app/dashboard.html",
    )
    return {"portal_url": session.url}


@router.post("/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Stripe sends signed webhooks. We verify the signature to prevent spoofing.
    """
    if not settings.STRIPE_SECRET_KEY or not settings.STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhook not configured.")

    import stripe
    stripe.api_key = settings.STRIPE_SECRET_KEY

    payload    = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, settings.STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature.")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payload.")

    event_type = event["type"]
    data_obj   = event["data"]["object"]

    if event_type == "checkout.session.completed":
        _handle_checkout_completed(data_obj, db)
    elif event_type in ("customer.subscription.updated", "customer.subscription.deleted"):
        _handle_subscription_change(data_obj, db)
    elif event_type in ("invoice.payment_failed", "invoice.payment_action_required"):
        _handle_payment_failed(data_obj, db)

    return {"received": True}


# ── Webhook handlers ──────────────────────────────────────────────────────────

def _handle_checkout_completed(session: dict, db: Session) -> None:
    user_id       = (session.get("metadata") or {}).get("user_id")
    plan          = (session.get("metadata") or {}).get("plan", "pro")
    billing_cycle = (session.get("metadata") or {}).get("billing_cycle", "monthly")
    subscription_id = session.get("subscription")

    if not user_id:
        return

    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        return

    user.plan = plan
    db.add(Subscription(
        user_id=user_id,
        stripe_subscription_id=subscription_id,
        plan=plan,
        billing_cycle=billing_cycle,
        status="active",
    ))
    db.commit()


def _handle_payment_failed(invoice: dict, db: Session) -> None:
    """Downgrade user immediately when a payment fails (before Stripe cancels)."""
    customer_id = invoice.get("customer")
    if not customer_id:
        return
    user = db.query(User).filter_by(stripe_customer_id=customer_id).first()
    if user and user.plan != "starter":
        user.plan = "starter"
        db.commit()


def _handle_subscription_change(subscription: dict, db: Session) -> None:
    stripe_sub_id = subscription.get("id")
    stripe_status = subscription.get("status")

    sub = db.query(Subscription).filter_by(stripe_subscription_id=stripe_sub_id).first()
    if not sub:
        return

    sub.status              = stripe_status
    sub.cancel_at_period_end = subscription.get("cancel_at_period_end", False)

    period_end = subscription.get("current_period_end")
    if period_end:
        sub.current_period_end = datetime.fromtimestamp(period_end, tz=timezone.utc)

    # Downgrade to starter if subscription cancelled / unpaid
    if stripe_status in ("canceled", "unpaid", "incomplete_expired"):
        user = db.query(User).filter_by(id=sub.user_id).first()
        if user:
            user.plan = "starter"

    db.commit()
