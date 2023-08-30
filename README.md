# devca
`devca` is a `keytool` frontend for development, because I can't be bothered to remember `keytool`'s arcane syntax.

## Description
`devca` allows you to quickly create a self-signed JKS certificate authority keystore and sub-keystores/truststores for development without remembering the moon runes necessary to get `keytool` to do what you want. **Do not use this in any production scenario**.

The default password on all keystores/truststores is `password`. This can be changed with the `--password` flag.

The default CN on all keystores/truststores is `localhost`. This can be changed with the `--cn` flag.

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
Create a new keystore called `ca.jks` in the current directory.
```
devca new ca
```

Create a new keystore called `server.jks` for `example.com`.
```
devca new ca --cn=example.com
```

Sign the keystore `server.jks` with another keystore `ca.jks`.
```
devca sign server ca
```

Create a keystore called `client.jks` expiring in 30 seconds.
```
devca new ca --expiry_seconds 30
```

Create a truststore called `client.truststore.jks` trusting `ca.jks` and `ca2.jks`.
```
devca mktrust client.truststore ca ca2
```

Wipe out all keystores/truststores in the current directory.
```
devca nuke
```

