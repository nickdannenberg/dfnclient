import json
from pathlib import Path
from sys import exit

import click
from termcolor import colored, cprint
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from dfngen import openssl, soap
import re

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
    (fqdn, pin, conf) = _gen_csr_common(fqdn, pin, applicant, config, additional, requestnumber, cert_profile)
    if conf["use_password"]:
        conf["password"] = click.prompt(
            colored("Enter a certificate password", "yellow"),
            hide_input=True,
            confirmation_prompt=True,
        )
    else:
        conf["password"] = None

    print("Generating private key and certificate signing request")
    req = openssl.gen_csr_with_new_cert(conf["fqdn"], conf["subject"],
                                        conf["password"], additional)

    soap.submit_request(req, onlyreqnumber=requestnumber, **conf)
    if not requestnumber:
        print("Generated pdf at:", colored("{}.pdf".format(fqdn)))
    with open("{}.conf".format(fqdn), "w") as f:
        f.write(json.dumps(conf, sort_keys=True, indent=4))


@cli.command("csr", help="Generate a certificate for an existing certificate (for FQDN with key stored in PATH).")
@click.argument("fqdn")
@click.argument("path", type=click.Path(exists=True))
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
def gen_existing(fqdn, pin, applicant, mail, config, path, additional, requestnumber, cert_profile):
    (fqdn, pin, conf) = _gen_csr_common(fqdn, pin, applicant, mail, config, additional, requestnumber, cert_profile)

    print("Checking key")
    with open(path, "rb") as f:
        try:
            serialization.load_pem_private_key(f.read(), None,
                                               default_backend())
        except TypeError:
            password = click.prompt(colored("Password needed", "yellow"),
                                    hide_input=True).encode()
        else:
            conf["password"] = None
    print("Generating certificate signing request")
    req = openssl.gen_csr_with_existing_cert(
        path,
        conf["fqdn"],
        conf["subject"],
        password=conf["password"],
        additional=additional,
    )

    soap.submit_request(req, onlyreqnumber=requestnumber, **conf)
    if not requestnumber:
        print("Generated pdf at:", colored("{}.pdf".format(fqdn)))


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

    soap.submit_request(req, onlyreqnumber=requestnumber, **conf)
    if not requestnumber:
        print("Generated pdf at:", colored("{}.pdf".format(fqdn)))


@cli.command("config", help="Creates or edits the default config file")
def create_config():
    config_edit()
    click.echo("Writing to config location")


# Helper Methods
def _prepare_common_args(fqdn, pin, applicant, mail, config, additional, requestnumber, cert_profile):
    "Common parsing/preparation code for all commands"
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
        if re.match('^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', alt) or re.match('^[0-9a-fA-F:]+', alt):
            conf['altnames'].append('IP:{}'.format(alt))
        else:
            conf['altnames'].append('DNS:{}'.format(alt))

    print("Generating certificate signing request with the following values:\n")
    for key, value in conf.items():
        if key in ('pin','password'):
            pass
        cprint("{}: {}".format(key, value), "yellow")
    click.confirm("Are these values correct?", default=True, abort=True)

    return (fqdn, pin, conf)


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
