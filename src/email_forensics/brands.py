"""Reference data for sender-identity checks: impersonated brands, free-mail and provider infrastructure.

These lists are deliberately short and editable. Organisation-specific domains
(your own, partners, suppliers) matter more than brands for BEC and are supplied
at run time with ``--protected-domain``.
"""

from __future__ import annotations

# Commonly impersonated brands: display-name words -> the brand's legitimate domains.
# Display-name words are matched as whole words, case-insensitively, except where a
# word is also a common English word or first name (those use a longer phrase).
BRANDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "microsoft": (("Microsoft", "Office 365", "Microsoft 365", "OneDrive", "SharePoint", "Microsoft Teams"),
                  ("microsoft.com", "office.com", "office365.com", "outlook.com", "live.com",
                   "microsoftonline.com", "sharepoint.com", "onedrive.com", "microsoft365.com")),
    "paypal": (("PayPal",), ("paypal.com",)),
    "apple": (("Apple", "iCloud", "Apple ID", "iTunes"), ("apple.com", "icloud.com")),
    "amazon": (("Amazon", "AWS"), ("amazon.com", "amazonaws.com")),
    "google": (("Google", "Gmail", "Google Workspace"), ("google.com", "gmail.com", "googlemail.com")),
    "facebook": (("Facebook", "Meta", "Instagram", "WhatsApp"),
                 ("facebook.com", "facebookmail.com", "meta.com", "instagram.com", "whatsapp.com")),
    "linkedin": (("LinkedIn",), ("linkedin.com",)),
    "netflix": (("Netflix",), ("netflix.com",)),
    "dhl": (("DHL",), ("dhl.com",)),
    "fedex": (("FedEx",), ("fedex.com",)),
    "ups": (("UPS",), ("ups.com",)),
    "usps": (("USPS",), ("usps.com",)),
    "docusign": (("DocuSign",), ("docusign.com", "docusign.net")),
    "dropbox": (("Dropbox",), ("dropbox.com",)),
    "adobe": (("Adobe", "Adobe Sign", "Acrobat"), ("adobe.com", "adobesign.com")),
    "wellsfargo": (("Wells Fargo",), ("wellsfargo.com",)),
    "chase": (("Chase Bank", "JPMorgan Chase"), ("chase.com", "jpmorgan.com")),
    "bankofamerica": (("Bank of America",), ("bankofamerica.com", "bofa.com")),
    "citibank": (("Citibank",), ("citibank.com", "citi.com")),
    "hsbc": (("HSBC",), ("hsbc.com",)),
    "americanexpress": (("American Express", "Amex"), ("americanexpress.com", "aexp.com")),
    "coinbase": (("Coinbase",), ("coinbase.com",)),
    "binance": (("Binance",), ("binance.com",)),
    "metamask": (("MetaMask",), ("metamask.io",)),
    "spotify": (("Spotify",), ("spotify.com",)),
    "yahoo": (("Yahoo",), ("yahoo.com", "yahoo-inc.com")),
    "att": (("AT&T",), ("att.com", "att.net")),
    "verizon": (("Verizon",), ("verizon.com",)),
    "irs": (("IRS", "Internal Revenue Service"), ("irs.gov",)),
    "walmart": (("Walmart",), ("walmart.com",)),
    "ebay": (("eBay",), ("ebay.com",)),
    "norton": (("Norton 360", "Norton Antivirus", "NortonLifeLock"), ("norton.com", "gen.com")),
    "mcafee": (("McAfee",), ("mcafee.com",)),
    "geeksquad": (("Geek Squad",), ("geeksquad.com", "bestbuy.com")),
    "okta": (("Okta",), ("okta.com",)),
    "salesforce": (("Salesforce",), ("salesforce.com",)),
    "intuit": (("Intuit", "QuickBooks", "TurboTax"), ("intuit.com", "quickbooks.com", "turbotax.com")),
    "booking": (("Booking.com",), ("booking.com",)),
    "airbnb": (("Airbnb",), ("airbnb.com",)),
    "zoom": (("Zoom Video", "Zoom Meetings"), ("zoom.us", "zoom.com")),
}

FREEMAIL_DOMAINS = frozenset("""
    gmail.com googlemail.com outlook.com hotmail.com live.com msn.com yahoo.com ymail.com aol.com
    icloud.com me.com mac.com proton.me protonmail.com gmx.com gmx.de gmx.net web.de mail.com
    mail.ru yandex.ru yandex.com zoho.com tutanota.com tuta.io qq.com 163.com 126.com
""".split())

# Large mail providers: sender domains they host -> hostname suffixes their servers use.
# A message claiming such a sender but never touching these servers was not sent by them.
PROVIDER_INFRA: dict[str, tuple[frozenset[str], tuple[str, ...]]] = {
    "Google": (frozenset({"gmail.com", "googlemail.com"}), ("google.com", "gmail.com", "googlemail.com")),
    "Microsoft": (frozenset({"outlook.com", "hotmail.com", "live.com", "msn.com"}),
                  ("outlook.com", "hotmail.com", "live.com", "microsoft.com", "office365.com")),
    "Yahoo": (frozenset({"yahoo.com", "ymail.com", "aol.com"}), ("yahoo.com", "yahoodns.net", "aol.com")),
    "Apple": (frozenset({"icloud.com", "me.com", "mac.com"}), ("apple.com", "icloud.com", "me.com")),
}

# Message-ID domains that only the provider's own servers generate.
PROVIDER_MESSAGE_ID_SUFFIXES: dict[str, tuple[str, ...]] = {
    "Google": ("mail.gmail.com",),
    "Microsoft": ("outlook.com",),  # includes *.prod.outlook.com
    "Yahoo": ("mail.yahoo.com",),
}

# Words attackers append to a brand to make a convincing domain ("paypal-secure").
COMBO_KEYWORDS = frozenset("""
    secure security login signin verify verification account accounts support service services update
    billing auth online portal wallet team alert alerts help center notice mail web app id recovery
    payment payments invoice docs document share file files cloud my www
""".split())

# Brand labels that are ordinary words; used as subdomains or name parts they mean nothing alone.
GENERIC_BRAND_LABELS = frozenset("office live outlook apple amazon chase zoom booking meta gen citi att".split())
