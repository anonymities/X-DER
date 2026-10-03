# AutoBrowCertDetailExtractor

Reproduction of the **X-DER** method from the paper *"Research on Correctness and Security Detection of Digital Certificate Verification in Browsers"*: mutate real-world X.509 certificates at the **TLV structure level**, deploy them with a per-certificate Nginx server, and drive **three mainstream browsers (Chrome, Edge, Firefox)** through Playwright to expose **viewer** (certificate display) and **validator** (certificate verification) discrepancies across browsers.

The pipeline has two stages:

1. **Mutation** — `XDER/X-DER.py` generates mutated certificates from a seed library, in one of two modes.
2. **Cross-browser differential testing** — `BrowCertExtractor/diff_test.py` opens every mutated certificate in Chrome / Edge / Firefox, extracts viewer fields and verification error codes, and merges them into difference types.

## Project Structure

```
AutoBrowCertDetailExtractor/
├── XDER/                          # Mutation engine (TLV-aware, from the paper)
│   ├── X-DER.py                   # Entry: batch mutation (user / feedback mode)
│   ├── DERcert_util.py            # DER parsing / structuralization utilities
│   ├── ParseCerts/                # TLV parsing tree (TLVdumper, dump, parse_item)
│   ├── MutateCerts/               # Mutation strategies (mutate_strategy, back_repair,
│   │                              #   locate_oid, prikey_createpukey)
│   ├── SaveCerts/                 # Mutated certificate output (create_certfile, random_supplement)
│   ├── ca_suite/                  # CA key pairs (RSA1024~4096, ECDSA192~512)
│   ├── public_utils/              # verify_nginx (nginx deployability check), public_funcs, remove_floder
│   └── Guide/                     # feedback_guide (Algorithm 3 weights), diff_guide, code_guide
├── BrowCertExtractor/             # Cross-browser differential testing
│   ├── diff_test.py               # Entry: batch viewer + validator diff across 3 browsers
│   ├── config_server/             # Nginx per-cert config / start-stop, certutil CA store
│   ├── public_func/               # Viewer field extraction helpers, cache clearing, keyboard, index
│   ├── use_browsers/              # Playwright automation + error-code extraction
│   │                              #   (playwright_all_auto, ex_sc_code, auto_chrome/egde/firefox)
│   └── conf/                      # Firefox/Chrome viewer decoder assets (certviewer.mjs, omni.ja)
├── der/                           # Original (seed) certificate store
└── venv/                          # Python virtual environment (Playwright etc.)
```

Generated at runtime: `mutat_cert_user/` / `mutat_cert_feedback/` (mutated certificates, one folder per certificate: `<name>.crt` + `<name>CA.der`) and `../diff_log_user/` / `../diff_log_feedback/` (difference-type folders with per-certificate logs).

## Two Mutation Modes

`XDER/X-DER.py` picks the mode with the `MODE` variable at the bottom of the file (keep it consistent with `diff_test.py`).

| Mode | Selection logic | Config |
|---|---|---|
| **user** | Directly specify a target field and a mutation strategy — no random selection. | `USER_TARGET` (e.g. `'extension-san'`), `USER_STRATEGY` (e.g. `'change_tag'`) |
| **feedback** | Roulette-wheel selection (paper **Algorithm 3**): every mutation operation has a weight (init 1); pick one operation proportionally to its weight; when a discrepancy is found the weight is incremented (`FeedbackGuide.update`). | none — automatic |

Both modes run through `BatchMut_certs(floder, sample_num, mode, ...)`: randomly sample `sample_num` certificates from the seed library, parse each into a TLV tree (`ParseCerts`), apply the chosen mutation (`MutateCerts`), re-sign with a CA from `ca_suite` (`SaveCerts`), and verify nginx deployability (`verify_nginx`). Output goes to `mutat_cert_feedback/` or `mutat_cert_user/` depending on `SUFFIX`.

## Cross-Browser Differential Testing

`BrowCertExtractor/diff_test.py` iterates over every mutated certificate folder of the matching mode:

1. **Serve the certificate** — `broswer_nginx()` rewrites `nginx.conf` for the certificate, installs its CA into the system store via `certutil`, and starts Nginx on `https://X-DER.test.com:443`.
2. **Three browsers via Playwright** — Firefox, Edge, Chrome visit the URL; the script captures:
   - **Validator results**: SSL error codes per browser (`SEC_ERROR_*` for Firefox, `net::ERR_*` for Chromium) via `ex_sc_code`.
   - **Viewer content**: certificate details as displayed by each browser's built-in certificate viewer (Firefox `about:certificate`, Chromium viewer page).
3. **Merge difference types** — `diff()` compares the viewer field values across the three browsers and the validator error-code triple; every differing field (plus `verify_result`) becomes one entry of the difference dict.
4. **Save** — logs are written under `../diff_log<SUFFIX>/<date>/<field1-field2-...>/<cert>.txt`; the **folder name is the merged difference type** (viewer + validator combined). Certificates with no differences are skipped; nginx / Playwright failures and extraction errors are tolerated and skipped without stopping the batch.

## Usage

```bash
# 1. Generate mutated certificates (set MODE / USER_TARGET / USER_STRATEGY in X-DER.py)
python XDER/X-DER.py

# 2. Run cross-browser diff on the generated certificates (set the same MODE in diff_test.py)
python BrowCertExtractor/diff_test.py
```

> Run both scripts from the project root; they share the same `MODE` setting
> (`'feedback'` or `'user'`), which determines the `mutat_cert_*` and
> `diff_log_*` folders used.

## Requirements

- Windows, Python 3.11 (virtualenv `venv/` included)
- Installed browsers: Chrome, Edge, Firefox (headless-capable; system Firefox profile used for `about:certificate`)
- Dependencies: `playwright`, `cryptography`, `pyperclip` (see `venv/`)
- Nginx `nginx-1.23.1` bundled under `BrowCertExtractor/config_server/`
