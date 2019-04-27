# gAuthenticator

Fork of Google Authenticator PAM module to get two-factor authentication in linux.

## Build & install
```shell
./configure
make
sudo make install
```

If you don't have access to "sudo", you have to manually become "root" prior
to calling "make install".

## gAuthenticator is TOTP (time based) Authenticator for desktop

Support multiple accounts.
