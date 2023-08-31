#!/usr/bin/env python3

import argparse
import os
from subprocess import run, SubprocessError
from datetime import timedelta
from typing import List, Optional

_default_dir = os.curdir
_default_password = "password"
_print_keytool_cmd = False


def _kt_run(cmd: List[str], errmsg: str = "Shit's fucked.", **kwargs) -> str:
    if _print_keytool_cmd:
        print("Executing", ["keytool"] + cmd)
    r = run(["keytool"] + cmd, capture_output=True, **kwargs)
    if r.returncode != 0:
        raise SubprocessError(f"{errmsg}\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}")
    return str(r.stdout, "utf-8")


class DevCa:
    def __init__(self, root: str = _default_dir, password: str = _default_password):
        self.__root = root.rstrip("/")
        self.__password = password

        _kt_run([], "The keytool binary is not installed.")

    def __file_path(self, file: str):
        return f"{self.__root}/{file}"

    def keystore_path(self, name: str):
        return self.__file_path(f"{name}.jks")

    def keystore_exists(self, name: str) -> bool:
        return os.path.isfile(self.keystore_path(name))

    def describe_keystore(self, name: str) -> str:
        return _kt_run(["-list", "-v", "-keystore", self.keystore_path(name), "-storepass", self.__password, "-keypass",
                        self.__password], "Failed to describe keystore.")

    def list_keystores(self) -> List[str]:
        r = []
        for f in sorted(os.listdir(self.__root)):
            if f.endswith(".jks"):
                r.append(f[:-len(".jks")])
        return r

    def remove_keystore(self, name: str):
        if not os.path.isfile(self.keystore_path(name)):
            return
        return os.remove(self.keystore_path(name))

    def nuke(self):
        for ks in self.list_keystores():
            self.remove_keystore(ks)

    def __validity_args(self, validity: timedelta) -> List[str]:
        if validity.seconds == 0:
            return ["-validity", str(validity.days)]
        else:
            s = validity.seconds - 1
            days = validity.days + 1
            hour_delta = 23 - s // 3600
            minute_delta = 59 - (s % 3600) // 60
            second_delta = 59 - s % 60
            return ["-startdate", f"-{hour_delta}H-{minute_delta}M-{second_delta}S", "-validity", str(days)]

    def create_keystore(self, name: str, cn: Optional[str] = None,
                        validity: timedelta = timedelta(days=365), parent: Optional[str] = None):
        if cn is None:
            cn = name

        if validity.seconds == 0:
            days = validity.days
            hour_delta = 0
            minute_delta = 0
            second_delta = 0
        else:
            s = validity.seconds - 1
            days = validity.days + 1
            hour_delta = 23 - s // 3600
            minute_delta = 59 - (s % 3600) // 60
            second_delta = 59 - s % 60

        self.remove_keystore(name)
        _kt_run(["-genkeypair", "-keystore", self.keystore_path(name), "-alias", name, "-dname",
                 f"CN={cn}", "-keyalg", "RSA", "-ext", "KeyUsage:critical=keyCertSign,digitalSignature", "-ext",
                 "BasicConstraints:critical=ca:true", "-keypass", self.__password, "-storepass",
                 self.__password] + self.__validity_args(validity),
                "Failed to create keystore.")

        if parent is not None:
            self.__sign_keystore(name, parent, cn, validity)

    def ensure_created_keystore(self, name: str):
        if not self.keystore_exists(name):
            self.create_keystore(name)

    def create_csr(self, name: str) -> str:
        return _kt_run(
            ["-certreq", "-keystore", self.keystore_path(name), "-alias", name, "-keypass",
             self.__password, "-storepass", self.__password], "Failed to create certificate request.")

    def get_certificate(self, name: str) -> str:
        return _kt_run(["-exportcert", "-alias", name, "-keystore", self.keystore_path(name), "-rfc", "-keypass",
                        self.__password, "-storepass", self.__password], "Failed to get certificate.")

    def sign_csr(self, csr: str, signer: str, cn: str, validity: timedelta) -> str:
        return _kt_run(["-gencert", "-alias", signer, "-ext", "KeyUsage:critical=keyCertSign,digitalSignature", "-ext",
                        "BasicConstraints:critical=ca:true", "-ext", f"SubjectAlternativeName=dns:{cn}", "-rfc",
                        "-keystore", self.keystore_path(signer), "-keypass", self.__password, "-storepass",
                        self.__password] + self.__validity_args(validity), input=bytes(csr, "utf-8"),
                       errmsg="Failed to create CSR.")

    def import_certificate(self, name: str, alias: str, cert: str):
        _kt_run(
            ["-importcert", "-noprompt", "-alias", alias, "-keystore", self.keystore_path(name), "-keypass",
             self.__password, "-storepass", self.__password], "Failed to import certificate",
            input=bytes(cert, "utf-8"))

    def __sign_keystore(self, signee: str, signer: str, cn: str, validity: timedelta):
        self.import_certificate(signee, signer, self.get_certificate(signer))
        csr = self.create_csr(signee)
        cert = self.sign_csr(csr, signer, cn, validity)
        self.import_certificate(signee, signee, cert)

    def trust_keystore(self, name: str, to_trust: str):
        cert = self.get_certificate(to_trust)
        self.import_certificate(name, to_trust, cert)

    def create_truststore(self, name: str, trusted_names: List[str]):
        self.remove_keystore(name)
        for tn in trusted_names:
            self.trust_keystore(name, tn)


if __name__ == "__main__":
    common_options = argparse.ArgumentParser(add_help=False)
    common_options.add_argument("-p", "--password", dest="password",
                                help="The password used to 'encrypt' the keystores. Default 'password'",
                                default=_default_password)
    common_options.add_argument("-r", "--root", dest="root",
                                help="The root folder to perform operations in. Default current directory.",
                                default=_default_dir)
    common_options.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                                help="Print the `keytool` commands being run.",
                                default=False)

    create_options = argparse.ArgumentParser(add_help=False)

    parser = argparse.ArgumentParser(
        prog='devca',
        description='A `keytool` frontend for development.',
        parents=[common_options])

    subparsers = parser.add_subparsers(title="command", dest="command", required=True)

    describe_parser = subparsers.add_parser("describe", description="Describes a keystore.", parents=[common_options])
    describe_parser.add_argument("name", help="The name of the keystore to describe.")

    list_parser = subparsers.add_parser("ls", description="Lists all keystores.", parents=[common_options])

    new_parser = subparsers.add_parser("new", description="Creates a keystore/truststore.", parents=[common_options])

    new_subparsers = new_parser.add_subparsers(title="type", dest="type", required=True, help="What to create.")

    new_child_subparser = new_subparsers.add_parser("child", description="Create a child certificate.",
                                                    parents=[common_options])
    new_child_subparser.add_argument("name",
                                     help="The name of the keystore to create. If one already exists with this name, overwrites it.")
    new_child_subparser.add_argument("parent",
                                     help="The name of the parent to create this keystore as a child of. If one already exists with this name, overwrites it.")
    new_child_subparser.add_argument("-d", "--expiry_days", dest="days", type=int,
                                     help="The amount of days to expiration. This is additive with -s/--expiry_seconds. Default 90.",
                                     default=-1)
    new_child_subparser.add_argument("-s", "--expiry_seconds", dest="seconds", type=int,
                                     help="The amount of seconds to expiration. This is additive with -d/--expiry_days. Default 0.",
                                     default=0)
    new_child_subparser.add_argument("-c", "--cn", dest="cn",
                                     help="The CN of the certificate to make. By default, this is the given name.",
                                     default=None)

    new_root_subparser = new_subparsers.add_parser("root", description="Create a root certificate.",
                                                   parents=[common_options])
    new_root_subparser.add_argument("name",
                                    help="The name of the keystore to create. If one already exists with this name, overwrites it.")
    new_root_subparser.add_argument("-d", "--expiry_days", dest="days", type=int,
                                    help="The amount of days to expiration. This is additive with -s/--expiry_seconds. Default 90.",
                                    default=-1)
    new_root_subparser.add_argument("-s", "--expiry_seconds", dest="seconds", type=int,
                                    help="The amount of seconds to expiration. This is additive with -d/--expiry_days. Default 0.",
                                    default=0)
    new_root_subparser.add_argument("-c", "--cn", dest="cn",
                                    help="The CN of the certificate to make. By default, this is the given name.",
                                    default=None)

    new_truststore_subparser = new_subparsers.add_parser("truststore", description="Create a truststore.",
                                                         parents=[common_options])
    new_truststore_subparser.add_argument("name",
                                          help="The name of the truststore to create. If one already exists with this name, overwrites it.")
    new_truststore_subparser.add_argument("to_trust",
                                          help="The names of the keystores to put in the truststore.", nargs="+")

    nuke_parser = subparsers.add_parser("nuke", description="Removes all keystores.", parents=[common_options])

    rm_parser = subparsers.add_parser("rm", description="Removes a keystore.", parents=[common_options])
    rm_parser.add_argument("name", help="The name of the keystore to remove if it exists.")

    trust_parser = subparsers.add_parser("trust",
                                         description="Make a keystore trust another keystore. This does not sign either keystore.",
                                         parents=[common_options])
    trust_parser.add_argument("name",
                              help="The name of the keystore that should trust the other certificate.")
    trust_parser.add_argument("to_trust",
                              help="The name of the keystore to trust.")

    options = parser.parse_args()

    _print_keytool_cmd = options.verbose
    ctx = DevCa(root=options.root, password=options.password)

    if options.command == "describe":
        print(ctx.describe_keystore(options.name))
    elif options.command == "ls":
        print("\n".join(ctx.list_keystores()))
    elif options.command == "new":
        if options.type == "truststore":
            ctx.create_truststore(options.name, options.to_trust)
        else:
            if options.days < 0:
                if options.seconds > 0:
                    options.days = 0
                else:
                    options.days = 90

            if options.type == "root":
                ctx.create_keystore(options.name, options.cn, timedelta(days=options.days, seconds=options.seconds))
            elif options.type == "child":
                ctx.create_keystore(options.name, options.cn, timedelta(days=options.days, seconds=options.seconds),
                                    options.parent)
            else:
                new_parser.print_usage()
                exit(1)
    elif options.command == "nuke":
        ctx.nuke()
    elif options.command == "rm":
        ctx.remove_keystore(options.name)
    elif options.command == "trust":
        ctx.trust_keystore(options.name, options.to_trust)
    else:
        parser.print_help()
