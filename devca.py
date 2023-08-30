import argparse
import os
from subprocess import run, SubprocessError
from datetime import timedelta
from typing import List

_default_dir = os.curdir
_default_password = "password"
_default_cn = "localhost"
_print_keytool_cmd = False


def _kt_run(cmd: List[str], errmsg: str = "Shit's fucked.", **kwargs) -> str:
    if _print_keytool_cmd:
        print("Executing", ["keytool"] + cmd)
    r = run(["keytool"] + cmd, capture_output=True, **kwargs)
    if r.returncode != 0:
        raise SubprocessError(f"{errmsg}\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}")
    return str(r.stdout, "utf-8")


class DevCa:
    def __init__(self, root: str = _default_dir, password: str = _default_password, cn: str = _default_cn):
        self.__root = root.rstrip("/")
        self.__password = password
        self.__cn = cn

        _kt_run([], "The keytool binary is not installed.")

    def __file_path(self, file: str):
        return f"{self.__root}/{file}"

    def keystore_path(self, name: str):
        return self.__file_path(f"{name}.jks")

    def keystore_exists(self, name: str) -> bool:
        return os.path.isfile(self.keystore_path(name))

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

    def create_keystore(self, name: str, validity: timedelta = timedelta(days=90)):
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
                 f"CN={self.__cn}", "-keyalg", "RSA", "-startdate", f"-{hour_delta}H-{minute_delta}M-{second_delta}S",
                 "-validity", str(days), "-keypass", self.__password, "-storepass", self.__password],
                "Failed to create keystore.")

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

    def sign_csr(self, csr: str, signer: str) -> str:
        return _kt_run(["-gencert", "-alias", signer, "-ext", "KeyUsage:critical=keyCertSign", "-ext",
                        f"SubjectAlternativeName=dns:{self.__cn}", "-rfc", "-keystore", self.keystore_path(signer),
                        "-keypass", self.__password, "-storepass", self.__password], input=bytes(csr, "utf-8"),
                       errmsg="Failed to create CSR.")

    def import_certificate(self, name: str, alias: str, cert: str):
        _kt_run(
            ["-importcert", "-noprompt", "-alias", alias, "-keystore", self.keystore_path(name), "-keypass",
             self.__password, "-storepass", self.__password], "Failed to import certificate",
            input=bytes(cert, "utf-8"))

    def sign_keystore(self, signee: str, signer: str):
        csr = self.create_csr(signee)
        cert = self.sign_csr(csr, signer)
        self.import_certificate(signee, signer, cert)

    def trust_keystore(self, name: str, to_trust: str):
        cert = self.get_certificate(to_trust)
        self.import_certificate(name, to_trust, cert)

    def create_truststore(self, name: str, trusted_names: List[str]):
        self.remove_keystore(name)
        for tn in trusted_names:
            self.trust_keystore(name, tn)


if __name__ == "__main__":
    common_options = argparse.ArgumentParser(add_help=False)
    common_options.add_argument("-c", "--cn", dest="cn", help="The common name to use. Default 'localhost'",
                                default=_default_cn)
    common_options.add_argument("-p", "--password", dest="password",
                                help="The password used to 'encrypt' the keystores. Default 'password'",
                                default=_default_password)
    common_options.add_argument("-r", "--root", dest="root",
                                help="The root folder to perform operations in. Default current directory.",
                                default=_default_dir)
    common_options.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                                help="Print the `keytool` commands being run.",
                                default=False)

    parser = argparse.ArgumentParser(
        prog='devca',
        description='A `keytool` frontend for development.')

    subparsers = parser.add_subparsers(title="command", dest="command", required=True)

    list_parser = subparsers.add_parser("ls", description="Lists all keystores.", parents=[common_options])

    mktrust_parser = subparsers.add_parser("mktrust", description="Creates a truststore.", parents=[common_options])
    mktrust_parser.add_argument("name",
                                help="The name of the keystore to create. If one already exists with this name, overwrites it.")
    mktrust_parser.add_argument("to_trust", help="The keystores to trust.", nargs="+")

    new_parser = subparsers.add_parser("new", description="Creates a keystore.", parents=[common_options])
    new_parser.add_argument("name",
                            help="The name of the keystore to create. If one already exists with this name, overwrites it.")
    new_parser.add_argument("-d", "--expiry_days", dest="days", type=int,
                            help="The amount of days to expiration. This is additive with -s/--expiry_seconds. Default 90.",
                            default=90)
    new_parser.add_argument("-s", "--expiry_seconds", dest="seconds", type=int,
                            help="The amount of seconds to expiration. This is additive with -d/--expiry_days. Default 0.",
                            default=0)

    nuke_parser = subparsers.add_parser("nuke", description="Removes all keystores.", parents=[common_options])

    rm_parser = subparsers.add_parser("rm", description="Removes a keystore.", parents=[common_options])
    rm_parser.add_argument("name", help="The name of the keystore to remove if it exists.")

    sign_parser = subparsers.add_parser("sign", description="Signs a keystore with another keystore.",
                                        parents=[common_options])
    sign_parser.add_argument("signee", help="The keystore to be signed.")
    sign_parser.add_argument("signer", help="The keystore to sign with.")

    options = parser.parse_args()

    _print_keytool_cmd = options.verbose
    ctx = DevCa(root=options.root, password=options.password, cn=options.cn)

    if options.command == "ls":
        print("\n".join(ctx.list_keystores()))
    elif options.command == "mktrust":
        ctx.create_truststore(options.name, options.to_trust)
    elif options.command == "new":
        ctx.create_keystore(options.name, timedelta(days=options.days, seconds=options.seconds))
    elif options.command == "nuke":
        ctx.nuke()
    elif options.command == "rm":
        ctx.remove_keystore(options.name)
    elif options.command == "sign":
        ctx.sign_keystore(options.signee, options.signer)
    else:
        parser.print_help()
