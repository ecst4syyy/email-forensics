# Email Forensics

Check whether an email is phishing or malware. Drop in a `.eml`, `.msg` or mailbox file and get a 0–100 risk score that explains itself.

![Email Forensics web app](docs/images/web-ui.png)

## Install

Needs Python 3.10+. No other dependencies.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install git+https://github.com/ecst4syyy/email-forensics
```

Or download the package file from [Releases](https://github.com/ecst4syyy/email-forensics/releases) and run `pip install email_forensics-*.whl`.

## Use

```bash
email-forensics serve                  # web app at http://127.0.0.1:8025
email-forensics analyze suspicious.eml # report in the terminal
```

Get the email as a file first: Outlook, drag it to the desktop. Gmail, "Show original" then "Download original".

## What it checks

- **Sender:** spoofing, lookalike domains (`paypa1.com`), SPF / DKIM / DMARC
- **Route:** delivery path and origin IP
- **Content:** dangerous links, hidden text, credential forms
- **Attachments:** macros, PDF scripts, shortcuts, archives, disguised executables
- **Exports:** HTML report, STIX / MISP / CSV indicators

Works offline. Nothing in the email is opened, run or sent anywhere.

## More

- [Full guide](docs/GUIDE.md): all options, REST API, automation, case management, finding codes
- [Changelog](docs/CHANGELOG.md) · [Roadmap](docs/ROADMAP.md)
