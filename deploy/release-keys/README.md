# Trusted release keys

The package installs every `*.pub` file of this directory (minisign public
keys) to `/etc/kernhaven/release-keys/`, where `kernhaven-upgrade` and
`install.sh` look for them (ADR-0013).

The directory is empty until the owner has created the release key in the
key ceremony (open item B-3). Until then upgrades refuse every release
unless a key is added on the host:

    install -m 0644 owner.pub /etc/kernhaven/release-keys/

Never commit a private key.
