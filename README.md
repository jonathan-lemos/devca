# devca
`devca` is a `keytool` frontend for development, because I can't be bothered to remember `keytool`'s arcane syntax.

## Description
`devca` allows you to quickly create a self-signed JKS certificate authority keystore and sub-keystores/truststores for development without remembering the moon runes necessary to get `keytool` to do what you want. **Do not use this in any production scenario**.

The default password on all keystores/truststores is `password`. This can be changed with the `--password` flag.

The default CN on all keystores is the name given. This can be changed with the `--cn` flag.

The default certificate expiry is 90 days. This can be changed with the `--expiry_days` and `--expiry_seconds` flags.

`devca` operates in your current directory by default. This can be changed with the `--root` flag.

The raw `keystore` commands can be printed with `--verbose` if you want to see them.

## Installation
Python 3.10+ is required to use `devca`. Copy it to any directory in `$PATH` and give it executable permission.
Alternatively, on Linux, you can
```
sudo make install
```
This will install it to /usr/local/bin. You can uninstall it with
```
sudo make uninstall
```

## Examples
Create a new root keystore called `ca.jks` in the current directory.
```
devca new root ca
```

Create a new root keystore called `ca.jks` with `CN=big bad root cert`.
```
devca new root ca --cn="big bad root cert"
```

Create a child of `ca.jks` called `server.jks` with `CN=localhost`.
```
devca new child server ca --cn=localhost
```

Create a child of `ca.jks` called `client.jks` expiring in 30 seconds.
```
devca new child client ca --expiry_seconds=30 
```

Create a truststore called `client.truststore.jks` trusting `ca.jks` and `ca2.jks`.
```
devca new truststore client.truststore ca ca2
```

Trust `ca2.jks` in `server.jks`. Note: this does not sign `server.jks` with `ca2.jks`.
```
devca trust server ca2
```

Wipe out all keystores/truststores in the current directory.
```
devca nuke
```

