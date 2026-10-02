"""Deterministic Nullapart-owned synthetic fixtures for the 8 gap classes.

No permissive real-world data exists for BusinessEmailCompromise, Spoofing,
AuthFailure, SuspiciousContent, MaliciousAttachment, PolicyViolation,
Reputation, or Unknown (plan decision 15). Fixtures are template-composed
with a fixed seed, carry explicit 13-label vectors, and emit the same
record shape as real sources so prepare_dataset.py treats them uniformly.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "data" / "synthetic" / "fixtures.jsonl"

LABELS = [
    "Malware",
    "Phishing",
    "Spam",
    "Spoofing",
    "BusinessEmailCompromise",
    "CredentialHarvest",
    "MaliciousUrl",
    "MaliciousAttachment",
    "SuspiciousContent",
    "PolicyViolation",
    "AuthFailure",
    "Reputation",
    "Unknown",
]

ORG_POOL = [
    "Northwind Logistics",
    "Halcyon Insurance",
    "Verdant Capital",
    "Meridian Health Group",
    "Portside Manufacturing",
    "Clearwater Utilities",
    "Ashford Legal",
    "Bluepeak Media",
]

ROLE_POOL = [
    ("Chief Executive Officer", "executive"),
    ("Finance Director", "finance"),
    ("Accounts Payable Manager", "finance"),
    ("IT Service Desk", "it"),
    ("HR Business Partner", "hr"),
    ("External Counsel", "legal"),
    ("Sales Operations Lead", "sales"),
]

AMOUNTS = ["$18,400.00", "$42,750.00", "GBP 9,600", "EUR 27,150", "$6,250.00"]

PAYEE_NAMES = ["Jordan Whitfield", "Casey Almeida", "Robin Okafor", "Sam Lindqvist"]

AUTH_PASS = (
    "mx.example.test; spf=pass smtp.mailfrom=sender.example; "
    "dkim=pass header.d=sender.example; dmarc=pass action=none"
)
AUTH_FAIL = (
    "mx.example.test; spf=fail smtp.mailfrom=attacker.example; "
    "dkim=fail header.d=attacker.example; dmarc=fail action=reject"
)
AUTH_SOFTFAIL = (
    "mx.example.test; spf=softfail smtp.mailfrom=sender.example; "
    "dkim=none; dmarc=quarantine"
)
AUTH_PERMERROR = (
    "mx.example.test; spf=permerror smtp.mailfrom=bounce; "
    "dkim=fail; dmarc=fail"
)

DEPARTMENTS = [
    "Treasury",
    "Field Operations",
    "Procurement",
    "Member Services",
    "Claims",
    "Platform Reliability",
    "Partner Success",
    "Records Management",
]

CITIES = [
    "Rotterdam",
    "Quesada",
    "Ulsan",
    "Wroclaw",
    "Traralgon",
    "Lulea",
    "Wichita Falls",
    "Gaborone",
]

MONTHS = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
]

DETAIL_AREAS = [
    "queued for the morning batch",
    "held pending your confirmation",
    "logged against the weekly review",
    "escalated after the first bounce",
    "cross-checked with the archive copy",
    "noted during the Friday sweep",
    "carried over from the prior cycle",
    "awaiting countersignature",
]


def detail_line(rng: random.Random) -> str:
    return (
        f"Ref {rng.randint(100000, 999999)} / {rng.randint(1, 28)} "
        f"{rng.choice(MONTHS)} — {rng.choice(DEPARTMENTS)}, "
        f"{rng.choice(CITIES)} office; {rng.choice(DETAIL_AREAS)}."
    )


def labels_for(*names: str) -> list[str]:
    return [name for name in LABELS if name in names]


def bec_record(rng: random.Random) -> dict:
    org = rng.choice(ORG_POOL)
    role, kind = rng.choice(ROLE_POOL)
    amount = rng.choice(AMOUNTS)
    payee = rng.choice(PAYEE_NAMES)
    variants = [
        (
            f"Urgent wire request — {org}",
            f"Please process a wire transfer of {amount} to {payee} today. "
            f"I am in back-to-back meetings so reply to this thread and treat "
            f"it as approved. Finance can reconcile after the fact.",
        ),
        (
            f"Updated banking details for {org} vendor payment",
            f"Our bank changed with the merger. Update the remittance "
            f"account before releasing the {amount} payment. Confirm once "
            f"the change is applied.",
        ),
        (
            f"Re: invoice reissue needed ({amount})",
            "The previous invoice bounced because of a treasury change. "
            "Reissue to this thread's account today; do not call the old "
            "number, I have a new secure line.",
        ),
        (
            f"{role} approval needed: {org} settlement",
            f"I need you to action the {amount} settlement without the "
            f"usual committee step. Board visibility is enough; reply "
            f"'approved' and I will forward to the bank.",
        ),
        (
            f"Gift card run for client recovery — {org}",
            f"Pick up {amount} in gift cards for a client make-good and "
            f"send the codes here. I will expense it when I land.",
        ),
    ]
    subject, body = rng.choice(variants)
    sender_name = rng.choice([r for r, _ in ROLE_POOL])[0]
    local = rng.choice(["office", "direct", "exec"])
    domain = org.lower().replace(" ", "") + "-group"
    return {
        "labels": labels_for("BusinessEmailCompromise"),
        "subject": subject,
        "body": body,
        "from_display": f"{sender_name} <ceo.{local}@{domain}.example>",
        "auth": AUTH_PASS,
        "urls": [],
        "attachment": None,
        "kind": kind,
    }


def spoofing_record(rng: random.Random) -> dict:
    org = rng.choice(ORG_POOL)
    brand = rng.choice(["Contoso Bank", "ParcelPost", "DocuSign-like", "CityPower"])
    variants = [
        (
            f"Password expiry notice — {org}",
            f"Your {org} mailbox password expires in 12 hours. Sign in at "
            f"the portal linked in the footer to keep access. IT Service Desk.",
        ),
        (
            f"Document shared with you ({brand})",
            f"{brand} shared 'Q4 settlement.pdf' with you. Open the link to "
            f"review; the share expires tomorrow.",
        ),
        (
            f"Your {brand} delivery could not be completed",
            "A parcel is on hold. Confirm your address details to release "
            "the delivery attempt scheduled for tomorrow.",
        ),
        (
            f"Action required on your {org} benefits record",
            "We could not verify your details. Confirm your information "
            "using the linked form to keep your benefits active.",
        ),
    ]
    subject, body = rng.choice(variants)
    fails = rng.random() < 0.5
    slug = brand.lower().replace(" ", "").replace("-", "")
    url = [f"https://{slug}.account-verify.example/session"]
    return {
        "labels": labels_for("Spoofing") + (labels_for("AuthFailure") if fails else []),
        "subject": subject,
        "body": body,
        "from_display": f"{brand} Security <security@{slug}.example>",
        "auth": AUTH_FAIL if fails else AUTH_SOFTFAIL,
        "urls": url if rng.random() < 0.6 else [],
        "attachment": None,
        "kind": "identity",
    }


def auth_failure_record(rng: random.Random) -> dict:
    org = rng.choice(ORG_POOL)
    variants = [
        (
            f"Re: scheduling with {org}",
            "Thanks for the note — sending this from my phone while the "
            "migration runs. Same agenda as before, see you Thursday.",
        ),
        (
            "Newsletter: monthly roundup",
            "This month's highlights from the team, plus two event "
            "invitations. Unsubscribe any time from the footer.",
        ),
        (
            "PO 4471 acknowledgment",
            "Received the purchase order, processing today. Tracking "
            "number follows once the warehouse confirms the pick.",
        ),
    ]
    subject, body = rng.choice(variants)
    style = rng.choice([AUTH_FAIL, AUTH_SOFTFAIL, AUTH_PERMERROR])
    return {
        "labels": labels_for("AuthFailure"),
        "subject": subject,
        "body": body,
        "from_display": f"{org} Dispatch <dispatch@{org.lower().replace(' ', '')}.example>",
        "auth": style,
        "urls": [],
        "attachment": None,
        "kind": "header-auth",
    }


def suspicious_content_record(rng: random.Random) -> dict:
    payloads = [
        "<script>fetch('https://collect.example/x')</script>",
        '<img src=x onerror="this.src=document.cookie">',
        "<div style='display:none'>verify your session now</div>",
        "&#87;&#105;&#110;&#110;&#111;&#119;",
        "javascript:alert(document.domain)",
    ]
    variants = [
        (
            "Security center alert",
            "Your session requires immediate verification. Continue below "
            "to restore full access to your account.",
        ),
        (
            "Critical update available",
            "Your system may be exposed. Call the support line shown to "
            "activate protection before the trial expires.",
        ),
        (
            "View the attached statement",
            "Please open the statement and confirm the figures shown.",
        ),
    ]
    subject, body = rng.choice(variants)
    payload = rng.choice(payloads)
    return {
        "labels": labels_for("SuspiciousContent"),
        "subject": subject,
        "body": f"{body}\n\n{payload}",
        "from_display": "Accounts Team <billing@notice-portal.example>",
        "auth": AUTH_SOFTFAIL,
        "urls": [],
        "attachment": None,
        "kind": "html-payload",
    }


def malicious_attachment_record(rng: random.Random) -> dict:
    files = [
        ("INVOICE_88431.zip", "password is invoice2026, as discussed"),
        ("Scan_0027.pdf", "enable macros to view the secure payload"),
        ("Remittance.adde", "opens in the native client"),
        ("Document.js", "review the generated document"),
        ("Q4_Budget.xlsm", "enable content to refresh the links"),
    ]
    name, hint = rng.choice(files)
    org = rng.choice(ORG_POOL)
    variants = [
        (f"Invoice attached — {org}", f"Attached is the revised invoice. {hint.capitalize()}."),
        ("Scanned document for review", f"Please review the scan. {hint.capitalize()}."),
        ("Payment advice", f"Advice for the payment run. {hint.capitalize()}."),
    ]
    subject, body = rng.choice(variants)
    suspicious = name.endswith((".js", ".xlsm", ".adde", ".zip"))
    return {
        "labels": labels_for("MaliciousAttachment")
        + (labels_for("SuspiciousContent") if suspicious and rng.random() < 0.35 else []),
        "subject": subject,
        "body": body,
        "from_display": f"{org} Billing <ap@{org.lower().replace(' ', '')}-docs.example>",
        "auth": AUTH_PASS,
        "urls": [],
        "attachment": {"filename": name, "content_type": "application/octet-stream"},
        "kind": "attachment-lure",
    }


def policy_violation_record(rng: random.Random) -> dict:
    org = rng.choice(ORG_POOL)
    variants = [
        (
            "Fwd: customer list for my side project",
            "Attached the full customer export — keep it off the shared "
            "drive so audit does not flag it again.",
        ),
        (
            "Re: credentials for the reporting box",
            "svc-report / Summer2026! — share it with the contractor, "
            "we can rotate after the engagement.",
        ),
        (
            "Offboarding workaround",
            "Copy the mailbox to a personal address before deprovision, "
            "then we can search it later if legal asks.",
        ),
        (
            "Bypass for the retention hold",
            "Purge the thread first; the hold policy only syncs nightly, "
            "so we have a window tonight.",
        ),
    ]
    subject, body = rng.choice(variants)
    has_attachment = rng.random() < 0.5
    return {
        "labels": labels_for("PolicyViolation"),
        "subject": subject,
        "body": body,
        "from_display": f"{org} Operations <ops@{org.lower().replace(' ', '')}.example>",
        "auth": AUTH_PASS,
        "urls": [],
        "attachment": {"filename": "export_full.csv", "content_type": "text/csv"}
        if has_attachment
        else None,
        "kind": "internal-policy",
    }


def reputation_record(rng: random.Random) -> dict:
    variants = [
        (
            "Re: complaint escalation from your sending domain",
            "Multiple recipients flagged your bulk send as deceptive. "
            "Postmaster review will downgrade the domain unless volume "
            "and list hygiene change this week.",
        ),
        (
            "Threat to publish: unsatisfied customer",
            "We will publish the complaint thread and name your company "
            "unless the refund is issued within 48 hours.",
        ),
        (
            "Co-brand request for your campaign",
            "We can run your offer to our list under your header — no "
            "need to update your existing suppression records.",
        ),
        (
            "Weekly wrap: what the feeds are saying",
            "Your domain appears in three reputation monitors this week; "
            "blocklist coverage rose after the partner blast.",
        ),
    ]
    subject, body = rng.choice(variants)
    return {
        "labels": labels_for("Reputation"),
        "subject": subject,
        "body": body,
        "from_display": "Postmaster Desk <postmaster@feeds-monitor.example>",
        "auth": AUTH_PASS,
        "urls": [],
        "attachment": None,
        "kind": "reputation-signal",
    }


def unknown_record(rng: random.Random) -> dict:
    variants = [
        (
            "Re: following up on the thread from Tuesday",
            "Circling back with the notes I have — not sure this belongs "
            "with ops or support, forwarding as received.",
        ),
        (
            "FW: mixed request",
            "Odd combination of invoice talk, a calendar invite, and a "
            "link I did not request. Flagging rather than deleting.",
        ),
        (
            "Undeliverable: partial bounce chain",
            "Delivery failed for part of the list; some recipients "
            "responded anyway. Unclear which leg produced the replies.",
        ),
        (
            "Question about the vendor portal",
            "Login page looked different than usual but the link came "
            "through the normal newsletter footer.",
        ),
    ]
    subject, body = rng.choice(variants)
    return {
        "labels": labels_for("Unknown"),
        "subject": subject,
        "body": body,
        "from_display": "Mixed Thread <notices@unclear-sender.example>",
        "auth": AUTH_SOFTFAIL if rng.random() < 0.4 else AUTH_PASS,
        "urls": ["https://portal.vendor-normal.example/login"] if rng.random() < 0.5 else [],
        "attachment": None,
        "kind": "ambiguous",
    }


def credential_harvest_record(rng: random.Random) -> dict:
    portal = rng.choice(
        [
            "webmail",
            "single-signon",
            "employee-portal",
            "vpn-access",
            "document-center",
            "hr-selfservice",
        ]
    )
    brand = rng.choice(["Northwind", "Halcyon", "Verdant", "Meridian", "Portside"])
    variants = [
        (
            f"Your {brand} password expires today",
            "Sign in within 12 hours to keep your mailbox active. "
            "Accounts that do not re-verify are suspended by policy.",
        ),
        (
            "Unusual sign-in detected — confirm it was you",
            "We saw a login from an unrecognised device. Open the "
            "verification page and enter your current credentials to "
            "restore full access.",
        ),
        (
            "Mailbox storage exceeded — re-authenticate now",
            "Delivery is paused until you confirm your account. Use "
            "the secure sign-in link below; the session token from "
            "last month is no longer valid.",
        ),
        (
            f"{brand} account review requires action",
            "Complete the identity check to avoid losing access to "
            "shared files and pending approvals.",
        ),
        (
            "Document access expired for your account",
            "Re-enter your username and password to extend access to "
            "the shared folder; otherwise the link stops working today.",
        ),
    ]
    subject, body = rng.choice(variants)
    slug = rng.randint(1000, 9999)
    return {
        "labels": labels_for("CredentialHarvest"),
        "subject": subject,
        "body": body,
        "from_display": f"{brand} Accounts <no-reply@{portal}-{slug}.example>",
        "auth": AUTH_SOFTFAIL if rng.random() < 0.7 else AUTH_FAIL,
        "urls": [f"https://{portal}-{slug}.example/login?session={slug}x9"],
        "attachment": None,
        "kind": "credential-lure",
    }


def malicious_url_record(rng: random.Random) -> dict:
    patterns = [
        "http://192.0.2.{}/account/update?u={}".format,
        "https://{}/redirect?u=aHR0cHM6Ly98next={}".format,
        "http://xn--{}-vda.example/verify".format,
        "https://{}-secure.login.portal.example/e?tk={}".format,
        "http://{}.bit-ly.top.example/{}".format,
        "https://{}:8443/owa/auth/logon.aspx?replace=1".format,
    ]
    forms = [
        (
            "Updated statement available",
            "Open the statement at {} to review the figures before close.",
        ),
        (
            "Parcel exception notice",
            "Reschedule the delivery at {} or the item returns to sender.",
        ),
        (
            "File shared with you",
            "The shared file is hosted at {} — access expires at midnight.",
        ),
        (
            "Password reset requested",
            "Confirm the reset request at {} to keep your account.",
        ),
        ("Survey invite", "Two questions at {} and we will stop writing."),
    ]
    subject, body_tpl = rng.choice(forms)
    host = rng.choice(["mail-update", "doc-view", "track-parcel", "verify-now", "inbox-sync"])
    url = rng.choice(patterns)(rng.randint(1, 254), rng.randint(10000, 99999))
    body = body_tpl.format(url)
    return {
        "labels": labels_for("MaliciousUrl"),
        "subject": subject,
        "body": body,
        "from_display": f"Notice Desk <alerts@{host}.example>",
        "auth": AUTH_SOFTFAIL,
        "urls": [url],
        "attachment": None,
        "kind": "url-payload",
    }


GENERATORS = {
    "BusinessEmailCompromise": bec_record,
    "CredentialHarvest": credential_harvest_record,
    "MaliciousUrl": malicious_url_record,
    "Spoofing": spoofing_record,
    "AuthFailure": auth_failure_record,
    "SuspiciousContent": suspicious_content_record,
    "MaliciousAttachment": malicious_attachment_record,
    "PolicyViolation": policy_violation_record,
    "Reputation": reputation_record,
    "Unknown": unknown_record,
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate synthetic fixtures for the 8 gap classes"
    )
    parser.add_argument("--per-class", type=int, default=1200)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    seen: set[str] = set()
    with OUT.open("w") as fh:
        for cls in sorted(GENERATORS):
            gen = GENERATORS[cls]
            for i in range(args.per_class):
                record = gen(rng)
                record["body"] = f"{record['body']} {detail_line(rng)}"
                row = {
                    "id": f"synthetic-{cls.lower()}-{i:05d}",
                    "source": "synthetic",
                    "source_detail": f"{cls}:{record['kind']}",
                    "labels": record["labels"],
                    "subject": record["subject"],
                    "body": record["body"],
                    "from_display": record["from_display"],
                    "auth": record["auth"],
                    "urls": record["urls"],
                    "attachment": record["attachment"],
                }
                key = re.sub(r"\s+", " ", f"{row['subject']} {row['body']}".lower()).strip()
                seen.add(key)
                fh.write(json.dumps(row, sort_keys=True) + "\n")
                for label in record["labels"]:
                    counts[label] = counts.get(label, 0) + 1
    total = args.per_class * len(GENERATORS)
    unique_ratio = len(seen) / total if total else 0.0
    if unique_ratio < 0.98:
        raise RuntimeError(f"text uniqueness too low: {unique_ratio:.3f} ({len(seen)}/{total})")
    stats = {
        "seed": args.seed,
        "per_class": args.per_class,
        "total_rows": total,
        "unique_text_ratio": round(unique_ratio, 4),
        "label_counts": dict(sorted(counts.items())),
        "label_vectors": LABELS,
    }
    stats_path = OUT.with_name("fixtures_stats.json")
    stats_path.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n")
    print(f"wrote {stats['total_rows']} fixtures -> {OUT.relative_to(ROOT)}")
    print(json.dumps(stats["label_counts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
