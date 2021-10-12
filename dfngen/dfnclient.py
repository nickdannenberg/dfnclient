import json
from pathlib import Path
from sys import exit

import click
from termcolor import colored, cprint
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from dfngen import openssl, soap, mail
import re

import datetime
import time
from random import choice
from string import ascii_uppercase, digits

APP_NAME = "dfnclient"
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

CONFIG = {
    "applicant": "John Doe",
    "mail": "john.doe@stud.example.com",
    "unit": "Department of Computer Science",
    "subject": {
        "country": "DE",
        "state": "Bundesland",
        "city": "Stadt",
        "org": "Testinstallation Eins CA",
        "cn": "{fqdn}",
    },
    "use_password": False,
    "raid": 101,
    "testserver": True,
}


@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    pass


@cli.command("create", help="Create a new certificate and signing request")
@click.argument("fqdn", required=False)
@click.option(
    "--pin",
    "-p",
    hide_input=True,
    confirmation_prompt=True,
    type=str,
    help="Applicant code pin, will be prompted if not provided",
)
@click.option("--applicant",
              type=str,
              help="Name of the applicant, defaults to value in config")
@click.option("--mail",
              type=str,
              help="Applicant email, defaults to value in config")
@click.option(
    "-c",
    "--config",
    type=click.Path(),
    help="Path to config",
    # show_default=True,
    default=Path(click.get_app_dir(APP_NAME)) / "config.json",
)
@click.option(
    "--additional",
    "-a",
    multiple=True,
    help=
    "Altnames for the certificate, provide multiple times for multiple entries",
)
@click.option(
    "--only-rq",
    "-r",
    "requestnumber",
    default=False,
    is_flag=True,
    help="Only print the request number and do not generate a pdf",
)
@click.option(
    "--cert-profile",
    type=str,
    help="Certificate profile, e.g. Web Server, LDAP Server"
)
def create_cert(fqdn, pin, applicant, mail, config, additional, requestnumber, cert_profile):
    (fqdn, pin, conf) = _gen_csr_common(fqdn, pin, applicant, mail, config, additional, requestnumber, cert_profile)
    if conf["use_password"]:
        conf["password"] = click.prompt(
            colored("Enter a certificate password", "yellow"),
            hide_input=True,
            confirmation_prompt=True,
        )
    else:
        conf["password"] = None

    say("Generating private key and certificate signing request")
    req = openssl.gen_csr_with_new_cert(conf["fqdn"], conf["subject"],
                                        conf["password"], additional)

    _submit_to_ca( req, onlyreqnumber=requestnumber, **conf)


@cli.command("csr", help="Generate a certificate for an existing certificate (for FQDN with key stored in PATH).")
@click.argument("fqdn")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--pin",
    "-p",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    type=str,
    help="Applicant code pin, will be prompted if not provided",
)
@click.option("--applicant",
              type=str,
              help="Name of the applicant, defaults to value in config")
@click.option("--mail",
              type=str,
              help="Applicant email, defaults to value in config")
@click.option(
    "-c",
    "--config",
    type=click.Path(),
    help="Path to config",
    # show_default=True,
    default=Path(click.get_app_dir(APP_NAME)) / "config.json",
)
@click.option(
    "--additional",
    "-a",
    multiple=True,
    help=
    "Altnames for the certificate, provide multiple times for multiple entries",
)
@click.option(
    "--only-rq",
    "-r",
    "requestnumber",
    default=False,
    is_flag=True,
    help="Only print the request number and do not generate a pdf",
)
@click.option(
    "--cert-profile",
    type=str,
    help="Certificate profile, e.g. Web Server, LDAP Server"
)
def gen_existing(fqdn, path, pin, applicant, mail, config, additional, requestnumber, cert_profile):
    (fqdn, pin, conf) = _gen_csr_common(fqdn, pin, applicant, mail, config, additional, requestnumber, cert_profile)

    say("Checking key")
    with open(path, "rb") as f:
        try:
            serialization.load_pem_private_key(f.read(), None,
                                               default_backend())
        except TypeError:
            password = click.prompt(colored("Password needed", "yellow"),
                                    hide_input=True).encode()
        else:
            conf["password"] = None
    say("Generating certificate signing request")
    req = openssl.gen_csr_with_existing_cert(
        path,
        conf["fqdn"],
        conf["subject"],
        password=conf["password"],
        additional=additional,
    )

    _submit_to_ca( req, onlyreqnumber=requestnumber, **conf)


@cli.command("submit", help="(Re)submit an existing certificate request (stored in CSR)")
@click.argument("csr", type=click.Path(exists=True))
@click.option("--applicant",
              type=str,
              help="Name of the applicant, defaults to value in config")
@click.option("--mail",
              type=str,
              help="Applicant email, defaults to value in config")
@click.option(
    "--pin",
    "-p",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    type=str,
    help="Applicant code pin, will be prompted if not provided",
)
@click.option(
    "-c",
    "--config",
    type=click.Path(),
    help="Path to config",
    # show_default=True,
    default=Path(click.get_app_dir(APP_NAME)) / "config.json",
)
@click.option(
    "--only-rq",
    "-r",
    "requestnumber",
    default=False,
    is_flag=True,
    help="Only print the request number and do not generate a pdf",
)
@click.option(
    "--cert-profile",
    type=str,
    help="Certificate profile, e.g. Web Server, LDAP Server"
)
def submit_csr(csr, pin, applicant, mail, config, requestnumber, cert_profile):
    (fqdn, additional, req) = openssl.data_from_csr(csr)
    (fqdn, pin, conf) = _prepare_common_args(fqdn, pin, applicant, mail, config, additional, requestnumber, cert_profile)
    conf['altnames'] = additional
    _submit_to_ca( req, onlyreqnumber=requestnumber, **conf)


@cli.command("send", help="Send certificate request PDF via email")
@click.argument("PDF", type=click.Path(exists=True))
@click.option(
    "--mail-to",
    help="E-Mail recipient address, defaults to applicant email"
)
@click.option(
    "--mail-from",
    help="E-Mail sender address, defaults to recipient email"
)
@click.option(
    "--use-smtp",
    default=False,
    is_flag=True,
    help="Use SMTP to send mail, defaults to off to use sendmail"
)
@click.option(
    "--mail-server",
    help="SMTP server to use, defaults to localhost"
)
@click.option(
    "-c",
    "--config",
    type=click.Path(),
    help="Path to config",
    # show_default=True,
    default=Path(click.get_app_dir(APP_NAME)) / "config.json",
)
def send_pdf(pdf, mail_from, mail_to, use_smtp, mail_server, config):
    if not(config):
        raise Exception("config empty")
    if(isinstance(config, dict)):
        conf = config
    else:
        conf = parse_config(config)
    if not(mail_to):
        try:
            mail_to = conf['mail_to']
        except:
            mail_to = conf['mail']
    if not(mail_from):
        try:
            mail_from = conf['mail_from']
        except:
            mail_from = mail_to
    if 'fqdn' in conf:
        # conf is a config for this host
        subj = f'DFN-PKI Certificate request for {conf["fqdn"]}'
        text = 'Please send sign this certificate request and send it to your CA.\n' \
            f'Hostname: {conf["fqdn"]}\n' \
            f'PIN: {conf["pin"]}\n' \
            f'Serial: {conf["serial"]}\n'
    else:
        subj = 'DFN-PKI Certificate request'
        text = 'Please send sign this certificate request and send it to your CA.'
    use_sendmail = conf['use_sendmail'] if 'use_sendmail' in conf else 1
    mailserver = conf['mailserver'] if 'mailserver' in conf else 'localhost'
    mail.send_mail(mail_to, mail_from, subj, text, files=[pdf], use_sendmail=not(use_smtp), server=mail_server )


@cli.command("download", help="Download certificate for outstanding certificate request")
@click.argument("config", type=click.Path(exists=True))
def download_cert(config):
    if(isinstance(config, dict)):
        conf = config
    else:
        conf = parse_config(config)
    fqdn = conf['fqdn']
    data = soap.download_certificate(**conf)
    if data:
        with open(f'{fqdn}.pem', 'w') as f:
            f.write(data)
        return True
    return False


@cli.command("autorenew", help="""Automatically renew certificate for FQDN.

When available, will use an existing CSR (so no access to the private
key is required). Otherwise, falls back to generating a new CSR from
an existing private key. To create a new private key, use the "create"
subcommand.

After submitting the CSR, the generated PDF, serial number and PIN
will be sent to the applicant's email address. FIXME: Is it a good
idea to send the PIN via email? This allows whoever gets access to the
email to revoke the certificate.

If a file FQDN.conf is present in the current directory, and it is
newer than the certificate, try to load FQDN.conf and download a new
certificate.
    """)
@click.argument("fqdn", type=str)
@click.option(
    "--min-valid-days",
    type=click.INT,
    help="Renew the certificate N days before expiry. defaults to 30"
)
@click.option(
    "--mail-to",
    help="E-Mail recipient address, defaults to applicant email"
)
@click.option(
    "--mail-from",
    help="E-Mail sender address, defaults to recipient email"
)
@click.option(
    "--use-smtp",
    default=False,
    is_flag=True,
    help="Use SMTP to send mail, defaults to off to use sendmail"
)
@click.option(
    "--mail-server",
    help="SMTP server to use, defaults to localhost"
)
def autorenew(fqdn, min_valid_days, mail_to, mail_from, use_smtp, mail_server):
    cert_path = Path(f"{fqdn}.pem")
    cfg_path = Path(f"{fqdn}.conf")
    pdf_path = Path(f"{fqdn}.pdf")
    if cfg_path.exists() and (not(cert_path.exists()) or
                              (cert_path.exists() and
                               cert_path.lstat().st_mtime < cfg_path.lstat().st_mtime)):
        #print('Try to download new certificate')
        ret = download_cert.callback(cfg_path)
        if ret:
            pdf_path.unlink()
            say('Downloaded new certificate')
            return True
        else:
            say('Could not download new certificate')
            return False
    else:
        cert_data = None
        if not(cfg_path and cfg_path.exists()) :
            # load default config
            cfg_path = Path(click.get_app_dir(APP_NAME)) / "config.json"
        conf = parse_config(cfg_path)
        if not(min_valid_days):
            try:
                min_valid_days = conf['min_valid_days']
            except:
                min_valid_days = 30
        conf['min_valid_days'] = min_valid_days

        if not(cert_path.exists()):
            say('No certificate -> request a new one')
        else:
            say('check if certificate should be renewed')
            cert_data = openssl.data_from_cert(cert_path)
            now = datetime.datetime.fromtimestamp(time.time())
            remaining = cert_data['not_valid_after'] - now
            if remaining.days <= min_valid_days:
                say(f'Only {remaining.days} days left, requesting new certificate')
            else:
                say(f'Certificate still valid for {remaining.days} days, NOT requesting new certificate')
                return True

        conf['fqdn'] = fqdn
        conf['config'] = cfg_path
        conf['batch'] = True
        if not('pin' in conf):
            conf['pin'] = generate_pin()
        req_path = Path(f'{fqdn}.req')
        key_path = Path(f'{fqdn}.key')
        if req_path.exists():
            say('CSR exists, sending again')
            conf['serial'] = submit_csr.callback( req_path, conf['pin'], conf['applicant'], conf['mail'], conf, 0, conf['profile'] )
        elif key_path.exists():
            say('No CSR found, generating new one for private key')
            conf['additional'] = []
            if cert_data and 'additional' in cert_data:
                conf['additional'] = [s.split(':')[1] for s in cert_data['additional'] if s.find(':')>-1]
            conf['serial'] = gen_existing.callback( fqdn, key_path, conf['pin'], conf['applicant'], conf['mail'], conf, conf['additional'], 0, conf['profile'])
        else:
            print('Neither CSR nor key found, cannot continue')
            return False

        if not(mail_to):
            try:
                mail_to = conf['mail_to']
            except:
                mail_to = conf['mail']
        if not(mail_from):
            try:
                mail_from = conf['mail_from']
            except:
                mail_from = mail_to

        return send_pdf.callback(pdf_path, mail_from, mail_to, use_smtp, mail_server, conf)


@cli.command("config", help="Creates or edits the default config file")
def create_config():
    config_edit()
    click.echo("Writing to config location")


# Helper Methods
def _prepare_common_args(fqdn, pin, applicant, mail, config, additional, requestnumber, cert_profile):
    "Common parsing/preparation code for all commands"
    if(isinstance(config, dict)):
        conf = config
    else:
        print("Using config: ", colored("{}".format(config), "blue"))
        conf = parse_config(config)
    check_conf(conf)
    if not "fqdn" in conf and fqdn is None:
        fqdn = click.prompt("Primary FQDN", type=str)
    if not "pin" in conf and pin is None:
        pin = click.prompt("PIN for DFN request",
                           hide_input=True,
                           confirmation_prompt=True,
                           type=int)
    if not "applicant" in conf:
        if applicant:
            conf["applicant"] = applicant
        else:
            conf["applicant"] = click.prompt(
                "No Applicant name provided, please enter")
    if not "mail" in conf:
        if mail:
            conf["mail"] = mail
        else:
            conf["mail"] = click.prompt(
                "No Applicant mail provided, please enter")
    conf["fqdn"] = fqdn
    # FIXME: bug, if pin is in conf but not given on the command line, it will be unset here
    if pin:
        conf["pin"] = pin
    if cert_profile:
        conf["profile"] = cert_profile
    elif not "profile" in conf:
        conf["profile"] = "Web Server"

    return (fqdn, pin, conf)

def _gen_csr_common(fqdn, pin, applicant, mail, config, additional, requestnumber, cert_profile):
    "Common functionality for preparing/generating a CSR"
    (fqdn, pin, conf) = _prepare_common_args(fqdn, pin, applicant, mail, config, additional, requestnumber, cert_profile)
    conf["subject"]["cn"] = conf["subject"]["cn"].format(**conf)
    conf["altnames"] = []
    for alt in additional:
        if re.match('^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', alt) or re.match('^[0-9a-fA-F:]+$', alt):
            conf['altnames'].append('IP:{}'.format(alt))
        else:
            conf['altnames'].append('DNS:{}'.format(alt))

    if 'batch' in conf and not(conf['batch']):
        print("Generating certificate signing request with the following values:\n")
        for key, value in conf.items():
            if key in ('pin','password'):
                pass
            cprint("{}: {}".format(key, value), "yellow")
        click.confirm("Are these values correct?", default=True, abort=True)

    return (fqdn, pin, conf)

def _submit_to_ca( req, onlyreqnumber, **conf):
    req_serial = soap.submit_request(req, onlyreqnumber=onlyreqnumber, **conf)
    conf['serial'] = req_serial
    fqdn = conf['fqdn']
    if not onlyreqnumber:
        if 'batch' in conf and not(conf['batch']):
            print("Generated pdf at:", colored("{}.pdf".format(fqdn)))
    with open("{}.conf".format(fqdn), "w") as f:
        f.write(json.dumps(conf, sort_keys=True, indent=4))
    return conf

pin_chars = digits + ascii_uppercase
def generate_pin(length=9):
    "Generate a random PIN"
    return ''.join(choice(pin_chars) for i in range(length))

def say(msg):
    # FIXME: make printing configurable
    if 0:
        print(msg)

def config_edit():
    config_directory = Path(click.get_app_dir(APP_NAME))
    if not config_directory.exists():
        config_directory.mkdir(parents=True)
    config_file_location = config_directory / "config.json"
    if config_file_location.exists():
        click.echo("Config already exists, opening in editor")
        click.edit(filename=config_file_location)
    else:
        click.echo("Creating file")
        output = click.edit(json.dumps(CONFIG, sort_keys=True, indent=4))
        with config_file_location.open("w") as f:
            f.write(output)


def parse_config(conf):
    conf_path = Path(conf)
    if not conf_path.exists():
        config_edit()
    with conf_path.open("r") as f:
        return json.loads(f.read())


def check_conf(conf):
    missing = [key for key in CONFIG.keys() if key not in conf.keys()]
    if len(missing) != 0:
        cprint("These keys are missing from your config", "red")
        cprint(missing, "yellow")
        cprint("Aborting", "red")
        exit(1)


if __name__ == "__main__":
    cli()
