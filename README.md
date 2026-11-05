# Phishing Email Investigation — DBS/POSB Digital Token Impersonation

**Assessment:** Suspected phishing based on impersonation and unexpected update request  
**Scope:** Static analysis of an email sample, authentication headers, message content, and third-party reputation lookups.

## 1. Findings

| Artifact | Observed value |
|---|---|
| Subject | `Account Notice: Digital Token Update Needed` |
| Display name | `DBS/POSB.` |
| From address | `noreply@substackss.firebaseapp.com` |
| Recipient | `[redacted]@gmail.com` (redacted for publication) |
| Message date/time | `2026-02-12 05:15:59 UTC` |
| Sending IP shown in authentication results | `209.85.222.71` |
| Message-ID | `0000000000008a523d064a99957c@google.com` |
| Call-to-action | `Update Your DBS Digital Token` |
| Link host identified in notes | `email[.]notify[.]thinkific[.]com` |
| SPF | `pass` |
| DKIM | `pass` (`header.d=firebaseapp.com`) |
| DMARC | `permerror`, `action=none` |
| Microsoft composite authentication | `pass`, `reason=111` |

**Key finding:** The email presents itself as a DBS/POSB banking notice, but the sender address is under `firebaseapp.com`. It urges the recipient to update a digital banking token through a link hosted under `thinkific.com`. This combination is consistent with a brand-impersonation phishing attempt.

> **About DBS/POSB from Wikipedia**
<img width="967" height="607" alt="image" src="https://github.com/user-attachments/assets/d5adb4ec-8cac-4c0d-abf7-10c0e5a405e8" />

## 2. Investigation Summary

On February 12, 2026, an email with the subject **“Account Notice: Digital Token Update Needed”** was sent using the display name **“DBS/POSB.”** The message stated that the recipient's digital banking token was no longer valid and informed the recipient to update it to avoid interruption of online banking services.

I reviewed the sender identity, public reputation information, email authentication results, and rendered message body. SPF and DKIM passed for the infrastructure/domains recorded in the headers; DMARC returned a permanent error. The message's banking-themed identity did not match its observed sender domain, and the update button referenced a third-party domain. These findings support a **phishing** classification.

## 3. Investigation Details

### Step 1 — Collect and document email metadata

The initial review recorded the subject, sender display name and email address, recipient, timestamp, sending IP, and Message-ID as documented above.

### Step 2 — Investigate the sender and infrastructure

I examined `firebaseapp.com` using VirusTotal and reviewed domain registration information. The notes show community reports concerning phishing-associated subdomains and identify the registrar as MarkMonitor Inc. I also checked IP reputation information in AbuseIPDB, including a lookup for `199.36.158.100`.

<img width="1910" height="3041" alt="image" src="https://github.com/user-attachments/assets/9e0a3ab3-b089-45f5-9d36-957769fa24ae" />

<img width="861" height="1448" alt="image" src="https://github.com/user-attachments/assets/b720b216-491e-49cf-9946-561575596519" />

<img width="1721" height="2161" alt="image" src="https://github.com/user-attachments/assets/260a1c4a-6756-4095-b87d-cb030b433a48" />

<img width="1147" height="453" alt="image" src="https://github.com/user-attachments/assets/b9540652-9e11-4f81-9403-732c49844233" />


### Step 3 — Examine email authentication

The recorded authentication results were:

```text
spf=pass (sender IP is 209.85.222.71)
smtp.mailfrom=substackss.firebaseapp.com;
dkim=pass (signature was verified)
header.d=firebaseapp.com;
dmarc=permerror action=none
header.from=substackss.firebaseapp.com;
compauth=pass reason=111
```

| Mechanism | Result | Meaning in this investigation |
|---|---|---|
| SPF | Pass | An approved list of mail server IPs that are authorized to send mail on behalf of the organization's domain. In this case, the sending IP, 209.85.222.71, is authorized to send mail on behalf of substackss.firebaseapp.com. |
| DKIM | Pass | When an email is sent, it uses a cryptographic signature to ensure that the message has not been modified. The sender signs the email with a private key and the recipient verifies using the DNS public key. |
| DMARC | Permanent error | DMARC checks whether the domain shown in the From email address aligns with the domain authenticated by SPF or DKIM. In this case, there is a permerror which could mean one of several causes. The main issue is that there is a misalignment between the email address in the From field and the domains authenticated by SPF and DKIM records. |
| Composite authentication | Pass | Microsoft email authentication assessment. It considers SPF, DKIM, DMARC, and other information to evaluate sender authenticity. |

### Step 4 — Analyze the message body and link

I rendered the email with [Sublime Security EML Analyzer](https://analyzer.sublime.security/). The email claimed that the recipient's digital token had expired or become invalid and instructed them to use the button **“Update Your DBS Digital Token.”** The button's link is:

```text
hxxps://email[.]notify[.]thinkific[.]com
```

The message applied an **account-access pretext** and encouraged the recipient to complete an update to preserve banking functionality. The use of a third-party link host for an alleged bank security update is suspicious in context.

<img width="719" height="1268" alt="image" src="https://github.com/user-attachments/assets/89ed989a-1dc8-4d00-b26e-81f5e6895ed0" />

The domain (thinkific.com) has been reported several times for malicious activities on VirtusTotal and Abuse IPDB.

<img width="1738" height="1846" alt="image" src="https://github.com/user-attachments/assets/a9208e85-1a70-4e74-b231-9d9f390936bf" />

### Step 5 — Correlate findings

The strongest indicators arise from the following evidence:

1. **Brand impersonation:** `DBS/POSB.` is presented as the sender while the actual sender uses `substackss.firebaseapp.com`.
2. **Security-update pretext:** The message claims the digital banking token must be updated.
3. **Suspicious call-to-action:** The recipient is directed toward `email[.]notify[.]thinkific[.]com`, rather than a verified bank-owned destination.

## 4. Indicators and Investigation Artifacts

| Type | Value | Context / handling |
|---|---|---|
| Sender address | `noreply@substackss.firebaseapp.com` | Observed sender; investigate for similar messages |
| Sender domain | `substackss.firebaseapp.com` | Observed in From and SPF mail-from fields |
| DKIM signing domain | `firebaseapp.com` | Authentication artifact; shared platform domain, not automatically malicious |
| Sending IP | `209.85.222.71` | Recorded in authentication result; not automatically malicious |
| Link host | `email[.]notify[.]thinkific[.]com` | Observed call-to-action host; verify complete URL and redirects before definitive classification |
| IP from separate lookup | `199.36.158.100` | Context-only reputation lookup; no confirmed direct connection to the sender IP |
| IP from separate lookup | `162.159.135.42` | Context-only reputation lookup; not proven malicious by the notes |
| Message-ID | `0000000000008a523d064a99957c@google.com` | Useful for email tracing and correlation |

## 6. Assessment and Verdict

**Verdict: Suspected phishing / DBS-POSB brand impersonation.**

The mismatch between the claimed banking identity and actual sender domain, together with the digital-token update pretext and third-party call-to-action host, supports treating the message as suspicious.

## 7. Tools and References

- [Sublime Security EML Analyzer](https://analyzer.sublime.security/) — email content rendering and inspection
- [VirusTotal](https://www.virustotal.com/) — domain reputation and community context
- [AbuseIPDB](https://www.abuseipdb.com/) — IP reputation context
- WHOIS/domain-registration lookup — registration context
- [MITRE ATT&CK T1566.002](https://attack.mitre.org/techniques/T1566/002/) — phishing link technique
