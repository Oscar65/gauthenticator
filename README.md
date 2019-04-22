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

## You can choose HOTP (counter based) or TOTP (time based)

The parameters are [-c counter] key

If you add -c counter and the key, cgoogle-authenticator returns HOTP (counter based) verification code.

If you only add the key, cgoogle-authenticator returns TOTP (time based) verification code.
