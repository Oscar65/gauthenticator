#include <libsecret/secret.h>

const SecretSchema * gauthenticator_get_schema_password (void) G_GNUC_CONST;

#define GAUTHENTICATOR_SCHEMA_PASSWORD  gauthenticator_get_schema_password ()

const SecretSchema * gauthenticator_get_schema_account (void) G_GNUC_CONST;

#define GAUTHENTICATOR_SCHEMA_ACCOUNT  gauthenticator_get_schema_account ()

const SecretSchema * gauthenticator_get_schema_unlock (void) G_GNUC_CONST;

#define GAUTHENTICATOR_SCHEMA_UNLOCK  gauthenticator_get_schema_unlock ()
