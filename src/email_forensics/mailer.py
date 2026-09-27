"""Fingerprinting of the sending software from X-Mailer / User-Agent and related headers."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class MailerSignature:
    pattern: re.Pattern
    name: str
    category: str  # "phishing-kit", "bulk", "script", "outdated", "client"


def _sig(pattern: str, name: str, category: str) -> MailerSignature:
    return MailerSignature(re.compile(pattern, re.I), name, category)


# Order matters: the first match wins, so specific kits come before the libraries they wrap.
SIGNATURES = (
    _sig(r"leaf\s*php\s*mailer", "Leaf PHPMailer", "phishing-kit"),
    _sig(r"alexus\s*mailer", "ALEXUS Mailer", "phishing-kit"),
    _sig(r"gammadyne", "Gammadyne Mass E-Mailer", "bulk"),
    _sig(r"atomic\s*mail\s*sender", "Atomic Mail Sender", "bulk"),
    _sig(r"sendblaster", "SendBlaster", "bulk"),
    _sig(r"advanced\s*mass\s*sender", "Advanced Mass Sender", "bulk"),
    _sig(r"epochta", "ePochta Mailer", "bulk"),
    _sig(r"group\s*mail", "Group Mail", "bulk"),
    _sig(r"phpmailer", "PHPMailer", "script"),
    _sig(r"swift\s*mailer", "SwiftMailer", "script"),
    _sig(r"symfony\s*mailer", "Symfony Mailer", "script"),
    _sig(r"nodemailer", "Nodemailer", "script"),
    _sig(r"^php/?\s*\d", "PHP mail()", "script"),
    _sig(r"python|smtplib", "Python", "script"),
    _sig(r"perl|mime::lite", "Perl", "script"),
    _sig(r"microsoft cdo", "Microsoft CDO (scripted Windows sending)", "script"),
    _sig(r"outlook express 6", "Outlook Express 6", "outdated"),
    _sig(r"microsoft outlook|microsoft office outlook", "Microsoft Outlook", "client"),
    _sig(r"thunderbird", "Mozilla Thunderbird", "client"),
    _sig(r"apple mail|iphone mail|ipad mail", "Apple Mail", "client"),
    _sig(r"roundcube", "Roundcube Webmail", "client"),
)


def fingerprint(value: str | None) -> MailerSignature | None:
    if not value:
        return None
    return next((s for s in SIGNATURES if s.pattern.search(value)), None)
