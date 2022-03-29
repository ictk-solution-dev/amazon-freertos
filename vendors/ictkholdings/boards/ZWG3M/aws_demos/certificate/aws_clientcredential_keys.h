#ifndef AWS_CLIENT_CREDENTIAL_KEYS_H
#define AWS_CLIENT_CREDENTIAL_KEYS_H


#define keyCLIENT_CERTIFICATE_PEM       "-----BEGIN CERTIFICATE-----\n"\
"MIIBijCCAS+gAwIBAgIUbQpvjBg7Hke2MNafNImJKN2CYscwCgYIKoZIzj0EAwIw\n"\
"QDELMAkGA1UEBhMCS1IxFjAUBgNVBAoMDUlDVEsgSG9sZGluZ3MxGTAXBgNVBAMM\n"\
"EElDVEsgSG9sZGluZ3MgQ0EwHhcNMTkxMTE5MDAwMTUzWhcNMjQxMTE3MDAwMTUz\n"\
"WjA6MQswCQYDVQQGEwJLUjEWMBQGA1UECgwNSUNUSyBIb2xkaW5nczETMBEGA1UE\n"\
"AwwKSUNUSyB0ZXN0MTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABERmcHZGJWJ9\n"\
"EXqdUl/Vrr8FIEpNBpyOUavqE5q7pmvxKJXjXREaZLfJW7t8z8dkgQaQlh2R2i42\n"\
"3HB8txBhEDGjDTALMAkGA1UdEwQCMAAwCgYIKoZIzj0EAwIDSQAwRgIhAPt6EY1K\n"\
"9AtoBquDRye3u/MgjIL5L41IjScI6HMeTNZZAiEAl7tuI5Z1SvsexZ7OypyJ2MOK\n"\
"WXQ+yGxFHjdXSkHh8Rg=\n"\
"-----END CERTIFICATE-----"
/*
 * @brief PEM-encoded issuer certificate for AWS IoT Just In Time Registration (JITR).
 *
 * @todo If you are using AWS IoT Just in Time Registration (JITR), set this to
 * the issuer (Certificate Authority) certificate of the client certificate above.
 *
 * @note This setting is required by JITR because the issuer is used by the AWS
 * IoT gateway for routing the device's initial request. (The device client
 * certificate must always be sent as well.) For more information about JITR, see:
 *  https://docs.aws.amazon.com/iot/latest/developerguide/jit-provisioning.html,
 *  https://aws.amazon.com/blogs/iot/just-in-time-registration-of-device-certificates-on-aws-iot/.
 *
 * If you're not using JITR, set below to NULL.
 *
 * Must include the PEM header and footer:
 * "-----BEGIN CERTIFICATE-----\n"\
 * "...base64 data...\n"\
 * "-----END CERTIFICATE-----\n"
 */
#define keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM    NULL

 /*
  * @brief PEM-encoded client private key.
  *
  * @todo If you are running one of the FreeRTOS demo projects, set this
  * to the private key that will be used for TLS client authentication.
  *
  * @note Must include the PEM header and footer:
  * "-----BEGIN RSA PRIVATE KEY-----\n"\
  * "...base64 data...\n"\
  * "-----END RSA PRIVATE KEY-----\n"
  */

#define keyCLIENT_PRIVATE_KEY_PEM   "-----BEGIN EC PRIVATE KEY-----\n"\
"MHcCAQEEIMJH6feyQfGoTEJfLvGDbRTi8/GxJaJuj483p5g+DkMQoAoGCCqGSM49\n"\
"AwEHoUQDQgAERGZwdkYlYn0Rep1SX9WuvwUgSk0GnI5Rq+oTmruma/EoleNdERpk\n"\
"t8lbu3zPx2SBBpCWHZHaLjbccHy3EGEQMQ==\n"\
"-----END EC PRIVATE KEY-----"
#endif /* AWS_CLIENT_CREDENTIAL_KEYS_H */