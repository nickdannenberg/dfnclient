# DFNClient

Forked from: [miterion on Github](https://github.com/miterion/dfnclient)

[![PyPI](https://img.shields.io/pypi/v/dfnclient?color=green&style=flat-square&link=https%3A%2F%2Fpypi.org%2Fproject%2Fdfnclient%2F)](https://pypi.org/project/dfnclient/)
[![Travis (.org)](https://img.shields.io/travis/miterion/dfnclient?style=flat-square&link=https%3A%2F%2Ftravis-ci.org%2Fgithub%2Fmiterion%2Fdfnclient%2F)](https://travis-ci.org/github/miterion/dfnclient)

A small python script to request certificates from the dfn

```
Usage: dfnclient [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  autorenew  Automatically renew certificate for FQDN
  config     Creates or edits the default config file
  create     Create a new certificate and signing request
  csr        Generate a certificate for an existing certificate (for FQDN...
  download   Download certificate for outstanding certificate request
  send       Send certificate request PDF via email
  submit     (Re)submit an existing certificate request (stored in CSR)

```

On a new system, use "create" to generate a new CSR. Then, for
subsequent renewals, use "autorenew".

In "autorenew" mode, the script will:

- Check if the existing certificate will expire soon. If it doesn't,
  stop.
- If no certificate exists, continue
- If no CSR exists, generate one from the private key
- Submit the CSR to CA via SOAP
- Send generated CSR-PDF and PIN via email to applicant
- Manual step: sign PDF and sends it to CA
- Periodically check if certificate was issued by CA, if so: download
  certificate


