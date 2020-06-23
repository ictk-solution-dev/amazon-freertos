/*
 *  X.509 test certificates
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/certs.h"

#if defined(MBEDTLS_CERTS_C)

#if defined(MBEDTLS_ECDSA_C)
#define TEST_CA_CRT_EC                                                  \
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"MIIBbDCCARGgAwIBAgIBATAKBggqhkjOPQQDAjA2MQswCQYDVQQGEwJLUjEOMAwG\r\n"  \
"A1UECgwFbG9jYWwxFzAVBgNVBAMMDjE5Mi4xNjguMjAuMTU4MB4XDTE5MDYwNTA1\r\n"  \
"NDM1OFoXDTI5MDYwMjA1NDM1OFowNjELMAkGA1UEBhMCS1IxDjAMBgNVBAoMBWxv\r\n"  \
"Y2FsMRcwFQYDVQQDDA4xOTIuMTY4LjIwLjE1ODBZMBMGByqGSM49AgEGCCqGSM49\r\n"  \
"AwEHA0IABCtqjF+wNeENo/WbXBRZFNJ5lWVcadwvPEDxpm4v61aCqWHxIOmMzvWV\r\n"  \
"RcHkHCVR8qByB+xUZwrOaHoIM+5VNiijEDAOMAwGA1UdEwQFMAMBAf8wCgYIKoZI\r\n"  \
"zj0EAwIDSQAwRgIhAKctz3bMqA0TSxhGE9QTMQHGZNc32Rq0ohgXaMzs+ucjAiEA\r\n"  \
"kQjEp8g+Uw80RKYGwfiziNLcwz+HLw5jburTNGi6JNU=\r\n"  \
"-----END CERTIFICATE-----\r\n"
const char mbedtls_test_ca_crt_ec[] = TEST_CA_CRT_EC;
const size_t mbedtls_test_ca_crt_ec_len = sizeof( mbedtls_test_ca_crt_ec );

const char mbedtls_test_ca_key_ec[] =
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEIPIszk5c+lNFJZNDuw35uKSoi7IXj4Dj9buqZ6aYuAvAoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEK2qMX7A14Q2j9ZtcFFkU0nmVZVxp3C88QPGmbi/rVoKpYfEg6YzO\r\n"
"9ZVFweQcJVHyoHIH7FRnCs5oeggz7lU2KA==\r\n"
"-----END EC PRIVATE KEY-----\r\n";
const size_t mbedtls_test_ca_key_ec_len = sizeof( mbedtls_test_ca_key_ec );

const char mbedtls_test_ca_pwd_ec[] = "PolarSSLTest";
const size_t mbedtls_test_ca_pwd_ec_len = sizeof( mbedtls_test_ca_pwd_ec ) - 1;

const char mbedtls_test_srv_crt_ec[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIBezCCASGgAwIBAgIUPhhvn3x5KGG4lInXngNMr+ps6fowCgYIKoZIzj0EAwIw\r\n"
"NjELMAkGA1UEBhMCS1IxDjAMBgNVBAoMBWxvY2FsMRcwFQYDVQQDDA4xOTIuMTY4\r\n"
"LjIwLjE1ODAeFw0xOTA2MDUwNTUwMzdaFw0yNDA2MDMwNTUwMzdaMDYxCzAJBgNV\r\n"
"BAYTAktSMQ4wDAYDVQQKDAVsb2NhbDEXMBUGA1UEAwwOMTkyLjE2OC4yMC4xNTgw\r\n"
"WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQkHiZztg60kgAkca8ewNuzlKElU39E\r\n"
"xcfx05Oyz8NYl106SI+ELWr8ueLpS3s2mxC7rM81gSmQ2IWsFP9KeX5uow0wCzAJ\r\n"
"BgNVHRMEAjAAMAoGCCqGSM49BAMCA0gAMEUCIHJ2Pxun/ERQ9NdXNMyd55TJtZI+\r\n"
"+Rgc3BoMbWF9hEfiAiEA3H3uP9uCNqNv9jeSle2jqtONuarJnGVYVIW0S35yiUA=\r\n"
"-----END CERTIFICATE-----\r\n";

const size_t mbedtls_test_srv_crt_ec_len = sizeof( mbedtls_test_srv_crt_ec );

const char mbedtls_test_srv_key_ec[] =
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEICDad5kR9V8Aa2HC2H5kC5+SgF+GUihfl5BsaugDcI/EoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEJB4mc7YOtJIAJHGvHsDbs5ShJVN/RMXH8dOTss/DWJddOkiPhC1q\r\n"
"/Lni6Ut7NpsQu6zPNYEpkNiFrBT/Snl+bg==\r\n"
"-----END EC PRIVATE KEY-----\r\n";
const size_t mbedtls_test_srv_key_ec_len = sizeof( mbedtls_test_srv_key_ec );

const char mbedtls_test_cli_crt_ec[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIBezCCASGgAwIBAgIUPhhvn3x5KGG4lInXngNMr+ps6fswCgYIKoZIzj0EAwIw\r\n"
"NjELMAkGA1UEBhMCS1IxDjAMBgNVBAoMBWxvY2FsMRcwFQYDVQQDDA4xOTIuMTY4\r\n"
"LjIwLjE1ODAeFw0xOTA2MDUwNTU3MzBaFw0yNDA2MDMwNTU3MzBaMDYxCzAJBgNV\r\n"
"BAYTAktSMQ4wDAYDVQQKDAVsb2NhbDEXMBUGA1UEAwwOMTkyLjE2OC4yMC4xNTgw\r\n"
"WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASmYzaupaVxEm/JLIdoeCuLyUZ2Gi8m\r\n"
"yow7Ru250piWU+KTiyrfzB1bBtXVbctflVxYlQJX66uigNZLt+Hg2LD+ow0wCzAJ\r\n"
"BgNVHRMEAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCEOzsH4POfxULFU5UjcpEvHccE\r\n"
"8eSKgeoX2yzfyrKBKQIgaik3duTvO/Q5jssCvabBq9TGTlKsdq1x6JRZYTKiTsY=\r\n"
"-----END CERTIFICATE-----\r\n";
const size_t mbedtls_test_cli_crt_ec_len = sizeof( mbedtls_test_cli_crt_ec );

const char mbedtls_test_cli_key_ec[] =
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEIC0iQ7jQvr10oZ6tG0vDLvS2qOOnuRiIbJxVUFc2USpyoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEpmM2rqWlcRJvySyHaHgri8lGdhovJsqMO0btudKYllPik4sq38wd\r\n"
"WwbV1W3LX5VcWJUCV+urooDWS7fh4Niw/g==\r\n"
"-----END EC PRIVATE KEY-----\r\n";
const size_t mbedtls_test_cli_key_ec_len = sizeof( mbedtls_test_cli_key_ec );

const char *mbedtls_test_ca_crt  = mbedtls_test_ca_crt_ec;
const char *mbedtls_test_ca_key  = mbedtls_test_ca_key_ec;
const char *mbedtls_test_ca_pwd  = mbedtls_test_ca_pwd_ec;
const char *mbedtls_test_srv_crt = mbedtls_test_srv_crt_ec;
const char *mbedtls_test_srv_key = mbedtls_test_srv_key_ec;
const char *mbedtls_test_cli_crt = mbedtls_test_cli_crt_ec;
const char *mbedtls_test_cli_key = mbedtls_test_cli_key_ec;
const size_t mbedtls_test_ca_crt_len  = sizeof( mbedtls_test_ca_crt_ec );
const size_t mbedtls_test_ca_key_len  = sizeof( mbedtls_test_ca_key_ec );
const size_t mbedtls_test_ca_pwd_len  = sizeof( mbedtls_test_ca_pwd_ec ) - 1;
const size_t mbedtls_test_srv_crt_len = sizeof( mbedtls_test_srv_crt_ec );
const size_t mbedtls_test_srv_key_len = sizeof( mbedtls_test_srv_key_ec );
const size_t mbedtls_test_cli_crt_len = sizeof( mbedtls_test_cli_crt_ec );
const size_t mbedtls_test_cli_key_len = sizeof( mbedtls_test_cli_key_ec );


#if defined(MBEDTLS_PEM_PARSE_C)
/* Concatenation of all available CA certificates */
const char mbedtls_test_cas_pem[] =
#ifdef TEST_CA_CRT_EC
    TEST_CA_CRT_EC
#endif
    "";
const size_t mbedtls_test_cas_pem_len = sizeof( mbedtls_test_cas_pem );
#endif

/* List of all available CA certificates */
const char * mbedtls_test_cas[] = {
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_test_ca_crt_ec,
#endif
    NULL
};
const size_t mbedtls_test_cas_len[] = {
#if defined(MBEDTLS_ECDSA_C)
  sizeof( mbedtls_test_ca_crt_ec ),
#endif
    0
};

#endif /* MBEDTLS_ECDSA_C */
#if 0
#if defined(MBEDTLS_LOCAL_SERVER_NAME) //based on local host MBEDTLS_LOCAL_SERVER_NAME
#if defined(MBEDTLS_RSA_C)

#if defined(MBEDTLS_SHA256_C)
#define TEST_CA_CRT_RSA_SHA256                                          \
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"MIIC7TCCAdWgAwIBAgIBATANBgkqhkiG9w0BAQsFADAxMQswCQYDVQQGEwJLUjEO\r\n"  \
"MAwGA1UECgwFbG9jYWwxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0xOTA0MjQwNjE0\r\n"  \
"MDhaFw0yOTA0MjEwNjE0MDhaMDExCzAJBgNVBAYTAktSMQ4wDAYDVQQKDAVsb2Nh\r\n"  \
"bDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\r\n"  \
"CgKCAQEAsCOCkuSgbG0rVgBT15WCMATAwxPiSfAnQYP0KAyaVMEWCEKSLCYZ1303\r\n"  \
"/21Ux6buO0yLnKpM/ChezGdiy0iJbF+BOBqrZW49DB7Ct17YSk5X5npJjQScoRIq\r\n"  \
"Ie/QzZt5WRj+LqYnxungt66U3ru4UbD/0OQdtmG+m8T16fU3RtDudZtFqudp027p\r\n"  \
"dH+rn9Ii2iEnS2NkVNWtHVoJFdaGRTB9DvEF+syIYp4H32aCltFnQlk5aHetV2J8\r\n"  \
"lU0eOPp3GiQ8Rguv+XRTrWmG1O8d2gFSxStoNzX1+C8I+0UmZ+bs9JIza+C0LYbi\r\n"  \
"M9ITu2bNFUDUB2EmYVjjMsN1fO4zCQIDAQABoxAwDjAMBgNVHRMEBTADAQH/MA0G\r\n"  \
"CSqGSIb3DQEBCwUAA4IBAQB050HYDOVw2BpxNuY/o0iwWNY6KJb6SS2UpHvQ6E+h\r\n"  \
"YXeuh0gaaXB2DKtOZKEcyYnQqh6oBjzGNugD+CrSrGY4XukkUCYtq6qCvo0SalQT\r\n"  \
"sNfla9gp/eMGR1l675NO3zY2UOOUH2ccyhMqT7DkdUcM7vLH+zuqAGzaYhquTUOo\r\n"  \
"8weidW4w+D7qY8nrqu4bF1w3ThqFOW0qBg4Jp8wwgb+yKBf7xxBgybisiCluCulj\r\n"  \
"RD0hWDd3hdVU3DqDJEa7HqeFi/EpT5/vRPMnloijIQnwLBN8plZLxQQ03/Shpl70\r\n"  \
"CTxbEVEuh+fuWf2FtXeAqE5Sw11ronAN0k/SHpH3to2l\r\n"  \
"-----END CERTIFICATE-----\r\n"



const char   mbedtls_test_ca_crt_rsa[]   = TEST_CA_CRT_RSA_SHA256;
const size_t mbedtls_test_ca_crt_rsa_len = sizeof( mbedtls_test_ca_crt_rsa );
#define TEST_CA_CRT_RSA_SOME

static const char mbedtls_test_ca_crt_rsa_sha256[] = TEST_CA_CRT_RSA_SHA256;

#endif

#if !defined(TEST_CA_CRT_RSA_SOME)
#define TEST_CA_CRT_RSA_SHA1                                            \
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"MIIDOzCCAiOgAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJLUjEW\r\n"  \
"MBQGA1UECgwNSUNUSyBIb2xkaW5nczEVMBMGA1UEAwwMMTkyLjE2OC4xLjc3MB4X\r\n"  \
"DTE5MDQyMzA1NTQzN1oXDTI5MDQyMDA1NTQzN1owPDELMAkGA1UEBhMCS1IxFjAU\r\n"  \
"BgNVBAoMDUlDVEsgSG9sZGluZ3MxFTATBgNVBAMMDDE5Mi4xNjguMS43NzCCASIw\r\n"  \
"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANXnrkTZifHz/c2bWQzq2HQQsx1d\r\n"  \
"cneeBjqykl4RyWhdrmHwd80yhUdk4LxbW7HOexR8Dt53V7d1TKBqnisQVMgDYcvj\r\n"  \
"3XKNYzSQTJ3cOYoCn337PlnCPoWjCY48Na7ZW8sFB+OWAS4KZWGk8xISnH6XHFsX\r\n"  \
"5uaopMpbQ8xLROj+F7wrzoCn0sR1yE5CBSp9vdGdB7UACw7dU9Dk/FRak3c+rUAJ\r\n"  \
"00RYcwtX7q5h85zEuEJUWfN6G3Sn9fdUZwn45goA6igHRyW5z5GxKVIbmKYfzfD6\r\n"  \
"mHJNuox2teFT/B97hyn7YfAAKSoicPx96Tfl0qWGhUCKw3tX3+juggfRapsCAwEA\r\n"  \
"AaNIMEYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUtCL/tBjsP8HZUoY6\r\n"  \
"5lbIcA6zm34wEQYJYIZIAYb4QgEBBAQDAgAHMA0GCSqGSIb3DQEBCwUAA4IBAQCb\r\n"  \
"C+qZZYSgRNB0yx6hwCQpLQWcBxzYABf6CPjRRmIfHW+QGklhrXdf8QmJyphT37sD\r\n"  \
"cOYhyTEmbG4behlijjTD6xqV9CLfqRUgPNl2tVCyWn4b/3Pn3Ci0SlPAjuhUUyX7\r\n"  \
"Qp4WFEZOeYIzWUWQuZzQBDp82C8HBsnR8Qpxj/SXUxfFTJtBPQnxQW23FOYU+SIG\r\n"  \
"z2L4L2pBeKPb7Misr11tDNTJoMDhuT7EdpTjgYtlzE106SIstcUnJAsQv+zQ6vDe\r\n"  \
"1YanBG0Ai60yEwbpwrwm/KLv4yn6iaR9LJZ/BACzEnFqktnEtz7w9IhJkvYlJ0Ed\r\n"  \
"u79WploZcWAC7E+1FXEu\r\n"  											\
"-----END CERTIFICATE-----\r\n"

#if !defined (TEST_CA_CRT_RSA_SOME)
const char   mbedtls_test_ca_crt_rsa[]   = TEST_CA_CRT_RSA_SHA1;
const size_t mbedtls_test_ca_crt_rsa_len = sizeof( mbedtls_test_ca_crt_rsa );
#endif

static const char mbedtls_test_ca_crt_rsa_sha1[] = TEST_CA_CRT_RSA_SHA1;

#endif

const char mbedtls_test_ca_key_rsa[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"Proc-Type: 4,ENCRYPTED\r\n"
"DEK-Info: AES-256-CBC,768C8896615DD97EC7F8FC10A0FB5A8C\r\n"
"\r\n"
"V6wNXqnbWCkcG0/s50ne/m+dJYQiKbpo1mqtBy0+uDk14L2EMOEhCQSjLbYUXFmR\r\n"
"5n+sJCxWVvbkOUCmX6lCvdwPiLHyJF9p2J6J03bbGlQGBgLFn7hjQ5cJUsyo1DaG\r\n"
"XLmeYfCFxZnS6Q2s75Hm+saH/+smrPvFcAQT7bmbJYVKsMdpynXKD4DL29j3aJl9\r\n"
"7aZ4mLYH6Moa88lOWChfTMxM1/6cvJJixNJg37YxLmpqh1C94louA0K1zWdiGl0S\r\n"
"L3JKKrhg7SBaUphR2+OzHeJBgTzjm7fsrQmrOSSpLtxUQfMDmThzno7hcn9H1T/T\r\n"
"fOUMreOKV1VJGTXv9YNaAilRsFF+U7puh0DOjGnBCcpOuIyOoux1JetLCGDnYR2M\r\n"
"LGNKp3TOr57oBU9UW3gtFXN3VG6Z/nJN1re1N4A37IeMekZ6n4vi0+25dgzw46k0\r\n"
"o8LQwdtrAIgK+fSvxwCqFDsPy3/DuKgSdRIVBAM9psdQyrdPniJFtmR/nd3SJdiP\r\n"
"yomBfFeas+D8MrjGgnkWx7FekkGNr3rrk1qEDg/jN9KfgcDJPah9H4aZmdpTMZ3h\r\n"
"rurkllcouX5x0tlR9jEm76pj+zLpr+zjvT9tl1UhtnUPFSN9eo3k0D68YdrCIge6\r\n"
"wNm5vOFfP8rzzotxX5FVvqP9TOEwY85OeCnqornmYnyK0X2eDFZiSrDMyjCn7z1Z\r\n"
"baJG/aDapiRUJweHEQrxLgDB+PjfOegMue8MhWSukgPQjM6EU2CmfYtzuxUuhrTT\r\n"
"yTG3s1iQw2rkcT7vzbwsbkS5ntgh9c3LdBhLvEteV6ZHlC83Py6wNdwB2KFGEAmN\r\n"
"Gy12MVa8Sraf9oek3eyBJDnVL5uMnFtKGU0aVcgsuJlxt3CEDAlFUn8o9m1/aPyt\r\n"
"FHZfX2FupRs9DHOLYZZtboW78JjBRd2rKNfnCzR4ziqGEmHUKwxh9P4CGRm4Lp+C\r\n"
"VZN5+szTm2vJRz6SWVXmdqJgT0zBJQawlKv9oYF0ORM3MGsG7YlQ1gjUjKLN1OZm\r\n"
"g76FaYITf8UaTkOV8RwF93DYh3jQbM0t6j3tIBKBDXKWcuI/8iJ5Zf01SgMJsd1K\r\n"
"SNeJfxwZq6wgn/2OxqMsr0Ezif+7V+IyjxDTBDL2k+Du9x5KBvQIs2+rcVmn6sZH\r\n"
"DuZdBKxxargRTKNfwxUZLuHbc/GyxvQw1dmqFi8IAg/dwc7XZlxRCeB4sfwwLzOO\r\n"
"AMqVIIw3513UzRZYmKT41ODIjElb60yuPDtSs/1hXz7pWRQr/S2U9Vkw12cTh12n\r\n"
"tIiq0wo4yox/sKVpkCDOKQ/thNJhWvJC/X/UvnIQ+gI9AQgBzRs/2P4tzRlLAYKf\r\n"
"LB2ANBtu9IPRHofQMYa5qHtJ987HYCyWPjHORYRuSse9QcVk2nohK92hxSjGqp24\r\n"
"MSFllFYVBKAaeSwFr9As5RQ0xKAR8wyKpaMYQHkq9A1YIFe3/4VO0+J3ywtx0nW9\r\n"
"JNJTLvfopmYAfVO0nzb/XxS4XpDyw2TgZKdGTyp/GN2Lax8bWpt0hy4kjmgkNx8y\r\n"
"gxBFI3TU+SsllBJHmCkoEHWn++6Zt9C5+GFJ/oH8O3fhc+d/b5UzVy3OJxtbQtyJ\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

const size_t mbedtls_test_ca_key_rsa_len = sizeof( mbedtls_test_ca_key_rsa );

const char mbedtls_test_ca_pwd_rsa[] = "ictk1234";//"PolarSSLTest";
const size_t mbedtls_test_ca_pwd_rsa_len = sizeof( mbedtls_test_ca_pwd_rsa ) - 1;

/* tests/data_files/server2.crt */
const char mbedtls_test_srv_crt_rsa[] =
"-----BEGIN CERTIFICATE-----\r\n"                                       
"MIIC/TCCAeWgAwIBAgIUMnFwq6Ty8ZAu7NtoRZ13EWrj8WAwDQYJKoZIhvcNAQEL\r\n"
"BQAwMTELMAkGA1UEBhMCS1IxDjAMBgNVBAoMBWxvY2FsMRIwEAYDVQQDDAlsb2Nh\r\n"
"bGhvc3QwHhcNMTkwNDI0MDYyMTQzWhcNMjQwNDIyMDYyMTQzWjAxMQswCQYDVQQG\r\n"
"EwJLUjEOMAwGA1UECgwFbG9jYWwxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJ\r\n"
"KoZIhvcNAQEBBQADggEPADCCAQoCggEBALY5jdHNyfnTOFIM5pI55R4UQZFdbIiv\r\n"
"JK9hgBtTe81BSnShRr6G7PAcxTAAVTkdhSFuJ8gy4n+wVyLgQpIttXJ3Qq/jb283\r\n"
"EZFmivn05CdO5viJz7a1quBCEiMpE6vhHCWdjJQl35DO89UWEwvBSqVYbp8H7CHD\r\n"
"IDHKEeGAZ0Zkxom+IDNRTI4a+7MvsihSXAyfaaExZ4ohUZssncGm8vdxlIZ5QxCQ\r\n"
"xyBNX0cyrLo0u7d1hrJS72WLfb23rGTPfx8LEcPvRTTcC8mCHOL7GoHrslB/5TMZ\r\n"
"BotpXCrxUh9Pukg7C2rTeLtsZ2d8ZHi3pptNP8dRFG+ITR3WxF+UcBUCAwEAAaMN\r\n"
"MAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOCAQEAi4/6ujQwqzVNwP3MDtWh\r\n"
"jF2w7568+Qq2bruDe5waHvOpgyA+tNgF4DhG/L2MCDHvL9Zr4mZfKRU4LIahpvRx\r\n"
"WYcbpU6dkptNinK5EHtilT1X1bUmgyyl0dSXm6SkcMPHEMPZuFB4pJrGLdd+s+Vo\r\n"
"g2g879XXheN1sx3rv6o5+j0/YPM0D0/Oc3qIx61TZgEX3JFPIoyGqkdHj/2jWA+X\r\n"
"KM0+gFdCnI528/lV2GPyvp3IqacO1ChXh4Bn2qSsHeLiBxCXpuAjlrVVI3Dv67Fm\r\n"
"68vqFSZlEe/js5lK2YSq6NBTiyKEawZa6SBG5VWV7aJKkwQg9fiiBmIqdnu1nPuV\r\n"
"Tw==\r\n"
"-----END CERTIFICATE-----\r\n";

const size_t mbedtls_test_srv_crt_rsa_len = sizeof( mbedtls_test_srv_crt_rsa );

/* tests/data_files/server2.key */
const char mbedtls_test_srv_key_rsa[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIIEogIBAAKCAQEAtjmN0c3J+dM4UgzmkjnlHhRBkV1siK8kr2GAG1N7zUFKdKFG\r\n"
"vobs8BzFMABVOR2FIW4nyDLif7BXIuBCki21cndCr+NvbzcRkWaK+fTkJ07m+InP\r\n"
"trWq4EISIykTq+EcJZ2MlCXfkM7z1RYTC8FKpVhunwfsIcMgMcoR4YBnRmTGib4g\r\n"
"M1FMjhr7sy+yKFJcDJ9poTFniiFRmyydwaby93GUhnlDEJDHIE1fRzKsujS7t3WG\r\n"
"slLvZYt9vbesZM9/HwsRw+9FNNwLyYIc4vsageuyUH/lMxkGi2lcKvFSH0+6SDsL\r\n"
"atN4u2xnZ3xkeLemm00/x1EUb4hNHdbEX5RwFQIDAQABAoIBAEPOyOIwZJ8tJQEL\r\n"
"QeVZ29NEkF2KWS/HlKwaaPRCLYhkalNaDBwr0xFKc2n4Rb46KOcWuYD6xmPjd5lH\r\n"
"wB3rGmDc1hjjVf0ZjdUARmja4udpqfMEPSHtGgfXLi6dQ2+rFbE9nikmqrmU+RDq\r\n"
"5O1z4NYEQS22YfzyQhGk8uBpyoRbrI1Z9yneNmBrjMUMH1moAaIN9E2s5B7UhovP\r\n"
"PKtQPwQaWtp0ooyte4/XD39I+kLqwS6bwRm0JIXizeCMdY0iUsf7MD6ZRGN5Z0iQ\r\n"
"wdwWNPGofW7huxj8iIeKsJaxM+oY/TJ1gZnq/dJkI//7FS/g4HI2YHqDrnbL4lUO\r\n"
"UyafZuUCgYEA57lFy5WNASlGhXWpK1x4sc2CB1zoh5S6lm3cTh6GA0+TYl7Nmvfe\r\n"
"jY3WfBwjLwvnzoWRsxHoAZ271jLzznqD4WDpDAlPoDVSAhsHhFIv5sDpfHzMXsp1\r\n"
"DFocYMDqUlYqVvgVLPW74pILsUZK93FxN/MDOSzqi7zr52YaOE2QkZcCgYEAyVC+\r\n"
"J1/OpHJ3gWSOUmqmr8ctBW6Azp6s7w03B0B8SqIMapn4t8wbWpKSxoG2JwFFkRug\r\n"
"Kduhhf4RmgHYEsNsweHNqbYH56C9SeT7HyIj14PF1AoxCDj3Gcyo7WrJDDN0RdTp\r\n"
"XzFowVKqGDn/X18oncIdV3SI5GXfDfBqYcGD6TMCgYAu7iYFkldJaeufcfH+Fy9W\r\n"
"i1GPXjC17NhRSRS6OZJYr1AhNyQbA6JuNtC+uBAkIhwjhoe4paLAWQrG2fDo24VE\r\n"
"KxVn26blwobGaGUAVojfCij/jmLxu70y8DkZG1kZrdvLW1kmjuore/qkP6FFNhOB\r\n"
"ClWXydIC1RNN/S7IQmVKJwKBgAMx1NKrIoxZhKv4/IkySBLiBkTfzAt7WSMyAn2K\r\n"
"+G32xFustdW013pIeSvNQya7Tm9PEOuZIKcPsRfQj608jK1G+AyJZva2Bkr150ZH\r\n"
"NGpnHOyQfNa0kLdIGCYsW6Rl7KJvDoUEM7VdqnVX9kV9LRfTzMNmhgWZ2EBQYF/M\r\n"
"wlshAoGAWlBriAvEQHygHwwIlH2n0cOUtSuZLz/r1ErmYSO7oI3T+CzPbukyvMVC\r\n"
"IAGGN8eek1ZAx4vQEfpVYA0xS3LU09NVDpOygFxCAmJIl8VgvX7QFOpju0Au86yu\r\n"
"TIcN+y4CO5divueGaFAlQBXs3Vr7X6kR0ZedYUM3Fvr4tvChSnc=\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

const size_t mbedtls_test_srv_key_rsa_len = sizeof( mbedtls_test_srv_key_rsa );

/* tests/data_files/cli-rsa-sha256.crt */
const char mbedtls_test_cli_crt_rsa[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIC/TCCAeWgAwIBAgIUMnFwq6Ty8ZAu7NtoRZ13EWrj8WEwDQYJKoZIhvcNAQEL\r\n"
"BQAwMTELMAkGA1UEBhMCS1IxDjAMBgNVBAoMBWxvY2FsMRIwEAYDVQQDDAlsb2Nh\r\n"
"bGhvc3QwHhcNMTkwNDI0MDYzNjI0WhcNMjQwNDIyMDYzNjI0WjAxMQswCQYDVQQG\r\n"
"EwJLUjEOMAwGA1UECgwFbG9jYWwxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJ\r\n"
"KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKAuGgjro6wOD3bkiuO+SNbAikVFk9HN\r\n"
"LOnCTj6+Nj2kYmFIGfNn7hnj+FW3eh834LTbnFZqH+tehA5lt/YOAlxiwpla2GWA\r\n"
"EjqE7C6Y5GBSFFjoP/iGQXDvb5duycQYvMQDJJxw4pwFXN2CV+o2H03M3jAafRd1\r\n"
"k4SkAj459XX7iT/iMLqLAX2SnlAzJCpOvIboSfzdV5DiTJ2Zj2JVKHOhOlFLNdmz\r\n"
"AJAoUERpYwmJjjqFIhRsPSWS34JJdVs0d74GNe0a0r5PL+trJq16OhsGudEV9W/n\r\n"
"ktERnyhACabVbcsUF2TOqozYrujsWI9hIlrtSo3Az6bAA06ese5FDacCAwEAAaMN\r\n"
"MAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOCAQEAgQNTzosj3gsPaw0LvYiR\r\n"
"/9phOIbA3s4id2cVNs4YGg32Sv/e80Fv9OnjAFJRI7GTQa/xiKBt25oDfGyhDMIn\r\n"
"Xodp2dMN6+tqCXmNl6YPVXZGL79gwSwky5NZH6psfGhiN68IFNFEQoYbh96/vmr6\r\n"
"oSg9w3KHr4E5qI/8ewRiKf6IZTUQfP7wEFXRC1fNYvEGPOvgbC79QAtxZqmna//6\r\n"
"+OIR6NulhO01lFjfonaiflvuh4jo9wzHaJ5fGgD374KYR5O61jyO9KqD5LbLTGGy\r\n"
"4QZ1OQ43XTlLdzE9//Qt6suSqsMCSkeeskjjKOIhAqJN4z4COXkeXflWq1aIDQ5s\r\n"
"BA==\r\n"
"-----END CERTIFICATE-----\r\n";
const size_t mbedtls_test_cli_crt_rsa_len = sizeof( mbedtls_test_cli_crt_rsa );

/* tests/data_files/cli-rsa.key */
const char mbedtls_test_cli_key_rsa[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIIEowIBAAKCAQEAoC4aCOujrA4PduSK475I1sCKRUWT0c0s6cJOPr42PaRiYUgZ\r\n"
"82fuGeP4Vbd6HzfgtNucVmof616EDmW39g4CXGLCmVrYZYASOoTsLpjkYFIUWOg/\r\n"
"+IZBcO9vl27JxBi8xAMknHDinAVc3YJX6jYfTczeMBp9F3WThKQCPjn1dfuJP+Iw\r\n"
"uosBfZKeUDMkKk68huhJ/N1XkOJMnZmPYlUoc6E6UUs12bMAkChQRGljCYmOOoUi\r\n"
"FGw9JZLfgkl1WzR3vgY17RrSvk8v62smrXo6Gwa50RX1b+eS0RGfKEAJptVtyxQX\r\n"
"ZM6qjNiu6OxYj2EiWu1KjcDPpsADTp6x7kUNpwIDAQABAoIBAH1nGmLZeG3/JARE\r\n"
"sKfUFVprqtTIwA2EwCDSSke8yuI/i/X1aLuzJimG3Kje1/EQ4g81z5Onyg2PFXvg\r\n"
"DsHH/fkuKIO/J6NvPNYrsmxYrpLqL5vbWBnNofY0vfykc7neVApxG3yOtBrJ6AZT\r\n"
"QVjPvno+ZcTrN/vhxPgXHtpwrccLRSzXPk0IcdCjKbhplSVnrhiYXGKdyL9FFCCY\r\n"
"nHd2hewLknffcfPYlbhQ3JWE4n0lfdp08j2JhmSSP4Bsbye7N1pPSlBCksZlPQx6\r\n"
"FcUHydXAzuPprJBS7T0C41K2ZpzGzk1IDcMLtExbF9eW2ZyWPYmKFNnGlaDL945A\r\n"
"Z1Bw2gECgYEAzieWcBjJ1z8u+dtisA/T2/n9NIBSaKJPHrMe+KNqaAXrJqCYA7XP\r\n"
"XthQI+dSgqldlS/k5AMqPWTwBqORgNeC25SpCI3+HsntyhW3CTwKESww+LvCvmMZ\r\n"
"K3OyDOpCi6+1DJZhAmDDexBttTKG39fW6zvOc8dJM4AvPD36IMXZLucCgYEAxujQ\r\n"
"YINih8fvKAVaVbuJP9P+/z0Q1YUwJrkE/dkRH7HcKfxpJJeh4fAsNiatQlvcZ9kY\r\n"
"r1YIrid0vnjp5FPnGgxkUa1c1R6r0tYWS/MOkkhz5b4L3PhU/fels5+s73M3txB2\r\n"
"1X6JuMvLIbHaPT7Gf17Jvxsci4dflGF+FJOTE0ECgYAzSHfM9O2pBQe7kg6vu5A5\r\n"
"ZavOVqmpa88A1RA8S/KZY/eGSWbnbV/juS3ecJn+9QDZrutiqULluOlYzXHRukrM\r\n"
"MuQFw8TWhecIYXSB8JSUhwi7p4GfeOl2/LXrLo9VTmVcd0A0pjuarpCMBcC1iGzn\r\n"
"YZ5PAOE91YJqmwRRCMapOwKBgQCyywDLUC4X+OqLIcyidZEYU5nJmf1wwGiY1gSb\r\n"
"nStcPwa0otNr9fSoX7eN8VQZ6vKCUk1zBbWFvaedspgjChwYeP0PwfJJC2nNeWzP\r\n"
"VipJ6WBsKVkGhh33r0w92pCbKAjzv5Phsf1fo6fyoKiYFr5cLTrRUjBlZwjOGpg3\r\n"
"LLOuQQKBgEMltaXaLBsXclJCoxrXYDa4SKJK664RQ4SrjP/ygcAknfqQAP3LX4+V\r\n"
"H+NjMBp2IeX2QxFWHOYjNMHgYpyXFuKE4QkqBomHhTr+3So97WFzWCrftdErlQE7\r\n"
"A2Zd3QTOIDpOGudqfZy0fB82loKjXUv5QAzTp1XX57NjnZ2icbzi\r\n"
"-----END RSA PRIVATE KEY-----\r\n";
const size_t mbedtls_test_cli_key_rsa_len = sizeof( mbedtls_test_cli_key_rsa );
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_PEM_PARSE_C)
/* Concatenation of all available CA certificates */
const char mbedtls_test_cas_pem[] =
//#ifdef TEST_CA_CRT_RSA_SHA1
//    TEST_CA_CRT_RSA_SHA1
//#endif
#ifdef MBEDTLS_RSA_C  
#ifdef TEST_CA_CRT_RSA_SHA256
    TEST_CA_CRT_RSA_SHA256
#endif
#else
#ifdef TEST_CA_CRT_EC
    TEST_CA_CRT_EC
#endif
#endif
    "";
const size_t mbedtls_test_cas_pem_len = sizeof( mbedtls_test_cas_pem );
#endif

/* List of all available CA certificates */
const char * mbedtls_test_cas[] = {
//#if defined(TEST_CA_CRT_RSA_SHA1)
//    mbedtls_test_ca_crt_rsa_sha1,
//#endif
#if defined(TEST_CA_CRT_RSA_SHA256)
    mbedtls_test_ca_crt_rsa_sha256,
#endif
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_test_ca_crt_ec,
#endif
    NULL
};
const size_t mbedtls_test_cas_len[] = {
//#if defined(TEST_CA_CRT_RSA_SHA1)
//    sizeof( mbedtls_test_ca_crt_rsa_sha1 ),
//#endif
#if defined(TEST_CA_CRT_RSA_SHA256)
    sizeof( mbedtls_test_ca_crt_rsa_sha256 ),
#endif
#if defined(MBEDTLS_ECDSA_C)
  sizeof( mbedtls_test_ca_crt_ec ),
#endif
    0
};

#else	//MBEDTLS_LOCAL_SERVER_NAME
#if defined(MBEDTLS_RSA_C)

#if defined(MBEDTLS_SHA256_C)
#define TEST_CA_CRT_RSA_SHA256                                          \
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"MIIDAzCCAeugAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJLUjEW\r\n"  \
"MBQGA1UECgwNSUNUSyBIb2xkaW5nczEVMBMGA1UEAwwMMTkyLjE2OC4xLjc3MB4X\r\n"  \
"DTE5MDQyNDAxMDY0MFoXDTI5MDQyMTAxMDY0MFowPDELMAkGA1UEBhMCS1IxFjAU\r\n"  \
"BgNVBAoMDUlDVEsgSG9sZGluZ3MxFTATBgNVBAMMDDE5Mi4xNjguMS43NzCCASIw\r\n"  \
"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM4hNJhxlG50d0dSggdgQ/DZ8ER2\r\n"  \
"vRZmpJ6VfO/2xebG4QocLpVBOc0ISwXpbW4UzQwjW+SECBiSp9C2oM9C+G5x45G0\r\n"  \
"5u53EYuXm8NR3s8Ly36Pi0IMXk7n341gbPj0sjPDVRti3uZXVeHErvGBFvYb49WM\r\n"  \
"nKO+371qKqwfzSwcQMTG0c0RPyr70yAvwim9oDaSYyazF3JzQS0ClbWhSi3bP9Gt\r\n"  \
"wpBRVCCsGPxU037GkubfY01U7oCTNhqoj4Ovo4SD6ybFHeUj62kC0GUVzQlXo7P4\r\n"  \
"2z6U3Xp9gRNW03PjoH/jJDwGc0vgphBaUDK7+z5Kvjk2w0n4XtgYQdFdR+ECAwEA\r\n"  \
"AaMQMA4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAnLxzB+GhhVKl\r\n"  \
"7bi8rEZf35zjwok5ZsgcLLXN4ZHaUIMCzAZV1rFYiWizMHKcsQYcC+f2Zn4zikpq\r\n"  \
"im/9FKhUim260SbeuBRZYuADwcCjL6tDREaawGTTUYV3jDSxUZrtP9Mu9Lnnfeln\r\n"  \
"GZQ4ZYYdG5FKJAxg1xZa4WifpYrfTx/JJ2IGCBPNBjMaGKfySTr/3iihrJQioOzR\r\n"  \
"ZiI0Z1XGmIxAJuf6jgs05XRi8VjU/qTzu/NmcXhyk3eXHVrfBTZ3JYRTMp3RAOg8\r\n"  \
"3mwEc5ESvUS2gvghRwIXI+2w+i6kzu8c7dHeQjJQ84L+uHc9pCATachVNWnCbzqt\r\n"  \
"FY5l9wBZuw==\r\n"	\
"-----END CERTIFICATE-----\r\n"



const char   mbedtls_test_ca_crt_rsa[]   = TEST_CA_CRT_RSA_SHA256;
const size_t mbedtls_test_ca_crt_rsa_len = sizeof( mbedtls_test_ca_crt_rsa );
#define TEST_CA_CRT_RSA_SOME

static const char mbedtls_test_ca_crt_rsa_sha256[] = TEST_CA_CRT_RSA_SHA256;

#endif
//#if !defined(TEST_CA_CRT_RSA_SOME) || defined(MBEDTLS_SHA1_C)

#if !defined(TEST_CA_CRT_RSA_SOME)
#define TEST_CA_CRT_RSA_SHA1                                            \
"-----BEGIN CERTIFICATE-----\r\n"                                       \
"MIIDOzCCAiOgAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJLUjEW\r\n"  \
"MBQGA1UECgwNSUNUSyBIb2xkaW5nczEVMBMGA1UEAwwMMTkyLjE2OC4xLjc3MB4X\r\n"  \
"DTE5MDQyMzA1NTQzN1oXDTI5MDQyMDA1NTQzN1owPDELMAkGA1UEBhMCS1IxFjAU\r\n"  \
"BgNVBAoMDUlDVEsgSG9sZGluZ3MxFTATBgNVBAMMDDE5Mi4xNjguMS43NzCCASIw\r\n"  \
"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANXnrkTZifHz/c2bWQzq2HQQsx1d\r\n"  \
"cneeBjqykl4RyWhdrmHwd80yhUdk4LxbW7HOexR8Dt53V7d1TKBqnisQVMgDYcvj\r\n"  \
"3XKNYzSQTJ3cOYoCn337PlnCPoWjCY48Na7ZW8sFB+OWAS4KZWGk8xISnH6XHFsX\r\n"  \
"5uaopMpbQ8xLROj+F7wrzoCn0sR1yE5CBSp9vdGdB7UACw7dU9Dk/FRak3c+rUAJ\r\n"  \
"00RYcwtX7q5h85zEuEJUWfN6G3Sn9fdUZwn45goA6igHRyW5z5GxKVIbmKYfzfD6\r\n"  \
"mHJNuox2teFT/B97hyn7YfAAKSoicPx96Tfl0qWGhUCKw3tX3+juggfRapsCAwEA\r\n"  \
"AaNIMEYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUtCL/tBjsP8HZUoY6\r\n"  \
"5lbIcA6zm34wEQYJYIZIAYb4QgEBBAQDAgAHMA0GCSqGSIb3DQEBCwUAA4IBAQCb\r\n"  \
"C+qZZYSgRNB0yx6hwCQpLQWcBxzYABf6CPjRRmIfHW+QGklhrXdf8QmJyphT37sD\r\n"  \
"cOYhyTEmbG4behlijjTD6xqV9CLfqRUgPNl2tVCyWn4b/3Pn3Ci0SlPAjuhUUyX7\r\n"  \
"Qp4WFEZOeYIzWUWQuZzQBDp82C8HBsnR8Qpxj/SXUxfFTJtBPQnxQW23FOYU+SIG\r\n"  \
"z2L4L2pBeKPb7Misr11tDNTJoMDhuT7EdpTjgYtlzE106SIstcUnJAsQv+zQ6vDe\r\n"  \
"1YanBG0Ai60yEwbpwrwm/KLv4yn6iaR9LJZ/BACzEnFqktnEtz7w9IhJkvYlJ0Ed\r\n"  \
"u79WploZcWAC7E+1FXEu\r\n"  											\
"-----END CERTIFICATE-----\r\n"

#if !defined (TEST_CA_CRT_RSA_SOME)
const char   mbedtls_test_ca_crt_rsa[]   = TEST_CA_CRT_RSA_SHA1;
const size_t mbedtls_test_ca_crt_rsa_len = sizeof( mbedtls_test_ca_crt_rsa );
#endif

static const char mbedtls_test_ca_crt_rsa_sha1[] = TEST_CA_CRT_RSA_SHA1;

#endif

const char mbedtls_test_ca_key_rsa[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"Proc-Type: 4,ENCRYPTED\r\n"
"DEK-Info: AES-256-CBC,55D30C739FA5FCA651C980D82FE1058C\r\n"
"\r\n"
"UGIgBTbyY70VvBN0KZ9MR4/hwYaLy1zVUGszWwzwFBgusYJ6np4cJzu9PPHYjBtw\r\n"
"tbeJ1HFcCzv+MBdbvVCF1uKliuyvOeQ6F65kx/bJpXkOLhoKsqRSHL78rkPYI0Gs\r\n"
"P7+/FVridLfhQdnzSSqgIh5RXMzLZ0/X23r5vuKWg/0XSlSFD4wgC7RQU0+22emy\r\n"
"2GPovWLfto5oWfKLSFx6tHPfT0l2VYbju1m5fLzt9GvEOWPkzs9ImjcgChM8PVMa\r\n"
"hkbLWOf+1YG25qLXmWZP8NY6BHZjzb9/clmXhU+IaTZ6Tc5e3tawBNOjV1JYEXda\r\n"
"7mCZxh6QO0hS32Ovx4BLgQoo3ExKEND0SpW6M01jffx4waXQMJJmbpXhEL1W1pUX\r\n"
"80FNR1+anEU4cX65Rv57gn5H25KG6mclNVv2w0RkqCmN2jrq46MCv8ju8i7REAj5\r\n"
"SVgjLN11N8Pwm3pB4jehmNdFNrzLH7ZmDkSIO6jBP8pjMYpNFGWZDnTl0Vhfo7Xy\r\n"
"mWpxxUi6M6BrVrhT5S15VdfVOaa8R+xWIO1SQj+uiEH1hPNgWbQZhfj8ru81aAbN\r\n"
"et7Ne4cUdZDHOlpjlnyGv8/bOEdUdDWpkZVYGAgWnSgM/BqfTflS/toDylYMWAwT\r\n"
"Hk6gljxH9kEko893HeLtJt3M2As9krADiV4YEppd05uvaFsIMmwOqSu9HwrWVNs1\r\n"
"zbl74rN/hFZVVvLUh6Q4dD5SxEPmp5Q5rUJUxk/FlitfNqe8AUmKeWgvHjc/eIze\r\n"
"vQ70CkclPe58Hayp55+9r/OG+jykyoOoeYsgh8o2voKN/6xzpnYHgSvQXJXWLRYj\r\n"
"NSlx2uBtwLLS4DDIj38L0dq4y+8pqDz2L21a8D0BYkc3X0PicnZ1BeUJHcgfB+Ox\r\n"
"5RZbYWlUSpEVdDYe62wLx/RjT+ffk2RKHuZtHIvRFcFJMwJOFZhODeZhxrlzIiWe\r\n"
"7NtJe9PyOFOctqvwpbT1ehFKx2Y2scLtI9NpH1UOq6lTfSSkejYBa2BMqECTCKFq\r\n"
"9Fhnw8uGEWyQWd05EN/4nE1xtUCwANUSjLq5EzAtYqBQIbFWJ1PjvpE4FReFYcv5\r\n"
"w6o+6LzNWTHPds8OymOx7a5jnQSdsJfjEczByK2c7CBWFnE68KK+K5ME9M6kEaqL\r\n"
"SfU1JnujFEnLfbDjURtbx9VTXzw5kheQfSPNxdmwJw4igsUlr/uK3YwH5lvQV/P2\r\n"
"9TTBqFWlgoQSG3wxQdKJo6Ti1IcARmnKjBYQOljIWKYanrmpFFNa5354+etgNDt5\r\n"
"5jSYd3w0FjbRejhc18fwTNwwtietuhm2AAD4f2LKF3FDmRwjDyZQvauy/nDxaA3+\r\n"
"uiz5VmKwMEmdESCagAAj8I5XwCokM/AE1vknRYjMbFrMioTTXWqmSDUJDlbRdbPP\r\n"
"widi8I5Nkybdo0e+Ezrn+jIFhvZUgyHCBSHEy/mfpwgtsmTyAfiypfCT7UHSQIa4\r\n"
"PiZI2M6t1gU5E6tghuTsaxsUMyewMKhurIL8EizAHlFfjFaz6MAbGQhygvP3gYyP\r\n"
"4xlUl6e7ly3+hDz1GhAB8P6i6XMcs6VPuKfvfwEnDcD5uQSOdmOKSGzQwhpi44pK\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

const size_t mbedtls_test_ca_key_rsa_len = sizeof( mbedtls_test_ca_key_rsa );

const char mbedtls_test_ca_pwd_rsa[] = "ictk1234";//"PolarSSLTest";
const size_t mbedtls_test_ca_pwd_rsa_len = sizeof( mbedtls_test_ca_pwd_rsa ) - 1;

/* tests/data_files/server2.crt */
const char mbedtls_test_srv_crt_rsa[] =
"-----BEGIN CERTIFICATE-----\r\n"                                       
"MIIDEzCCAfugAwIBAgIUIVbJxJATEG//QfkXw1S1tyuvvWQwDQYJKoZIhvcNAQEL\r\n"
"BQAwPDELMAkGA1UEBhMCS1IxFjAUBgNVBAoMDUlDVEsgSG9sZGluZ3MxFTATBgNV\r\n"
"BAMMDDE5Mi4xNjguMS43NzAeFw0xOTA0MjQwMTEyNTZaFw0yNDA0MjIwMTEyNTZa\r\n"
"MDwxCzAJBgNVBAYTAktSMRYwFAYDVQQKDA1JQ1RLIEhvbGRpbmdzMRUwEwYDVQQD\r\n"
"DAwxOTIuMTY4LjEuNzcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDP\r\n"
"9J/XKZMV5lVqk1l2Vr7I2oLvFcsRKiTL3fcIc59N/xSofxRj+t9ZFs6cArHcut3f\r\n"
"6g7qK4vpgAq7UvlN06n/62vHEoN3/AllN1G74Kh8FaYYb33rb+T9SOdlKfrBGwnl\r\n"
"qL8TUUvwrmd7s6XaEkdlwD5zPTSNEtc3r3dsC5UFcLkv8oU8JPvQGQlkvMwP5PL4\r\n"
"yOQWIHUWffj0G7z82XnyH4w9QMnvmps2cAymDMYww+qca8NGsElMMTjcMSbrK4bN\r\n"
"2BtzTm1JAg6c21LgbVH1e7OHogBmCaEgk04a2QqWSPs6JO6xBrpbLbA4vEcn3Y3A\r\n"
"K3rFo1bw2u/LFZL2XpO9AgMBAAGjDTALMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEL\r\n"
"BQADggEBAKJaMRf/8NiqDTRVbui0YiKvBzvue/42EfgOUC3ZLprmQenlunFaItma\r\n"
"7fRjnF5UCOzmgiyz4sMmwGKGr8eNaZDn4Kaq4QjbUslTPMM4uOsMlTY+3AJelai4\r\n"
"rQuVSXQ/SkXe7D1kz7l0LkhFZGRyXklRnLcvGI9YvhTKNIbUDfYQNi3AA/MdjowM\r\n"
"isgImbzS+c4De0rfn1pVcwB0VgLSK4fFfZ7bm4NB1uYY+IxEaLRbnotVFFNFiJ9A\r\n"
"E231+abkMhobEacJxrSr/7cVTH8twiBuJHFgNDnuAX/sYGyHpWLVSpqPTYYgie1F\r\n"
"wLBy3nVQac3KStQ/cBO6WjfI5+Hw7kg=\r\n"
"-----END CERTIFICATE-----\r\n";

const size_t mbedtls_test_srv_crt_rsa_len = sizeof( mbedtls_test_srv_crt_rsa );

/* tests/data_files/server2.key */
const char mbedtls_test_srv_key_rsa[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIIEpAIBAAKCAQEAz/Sf1ymTFeZVapNZdla+yNqC7xXLESoky933CHOfTf8UqH8U\r\n"
"Y/rfWRbOnAKx3Lrd3+oO6iuL6YAKu1L5TdOp/+trxxKDd/wJZTdRu+CofBWmGG99\r\n"
"62/k/UjnZSn6wRsJ5ai/E1FL8K5ne7Ol2hJHZcA+cz00jRLXN693bAuVBXC5L/KF\r\n"
"PCT70BkJZLzMD+Ty+MjkFiB1Fn349Bu8/Nl58h+MPUDJ75qbNnAMpgzGMMPqnGvD\r\n"
"RrBJTDE43DEm6yuGzdgbc05tSQIOnNtS4G1R9Xuzh6IAZgmhIJNOGtkKlkj7OiTu\r\n"
"sQa6Wy2wOLxHJ92NwCt6xaNW8NrvyxWS9l6TvQIDAQABAoIBAQChYKqx5Fd6RTa/\r\n"
"7/0a8pI3eCrnsrfVaCkJ9ASCkIdtlafIYmXGeKbeke5f709rhbAs1YwheQ2odG7f\r\n"
"k7JYDQv9yAnpgJp5gCMiYt2QuPTG5l3w1ISZMko3rF21ifBH7t2tVViCezI9Ynp3\r\n"
"6p+oLUsu0RMlhrfDSn2tfwNj21EX2E4LyoSa0sLHmH/Vt4UZjb6ggBzA5U5mxjoZ\r\n"
"x/ZjRpRWI0Li71pdd0rthRpr9hm6tbLYJ/zospnYRC3exouLcMzQiMSlF0uXdu/q\r\n"
"Hil8pYgitSxvCAr3MD0QsCQ2yFYGVEXyNf6nYfZaJTl3q6GRd793RV22qIlWc3/h\r\n"
"BrpgIcWBAoGBAOvdLEv86o7QZ+ULHgQNnCJwSWAqF3uREq0KoRHDrIXDCKEkhyeL\r\n"
"2IGeuHTdoanVEkAk8vhCi0sNLUNoRiDZFKwngL13BUizraC80DBghPBPk/le3A/Y\r\n"
"aszBn7Q79NZla7OOv+Sapzn9deut2NacZxOaxhMyrAKejQO5/RqRtiQtAoGBAOG1\r\n"
"gtJIUnfmWziNz+UwP0pBSevKcLs0WsBrk+/QuRoX9P8jtRE8asjmSrdHJv9R9jxz\r\n"
"2oAXoIkhJ+iC92zJbqY2fHgUm8V7+lIGG3xn+QdajinIqzs0qQGbwwB91JC8WDWv\r\n"
"3WYnznGd9YWtmtamvQikj7ZXEJP7Vtw1Te4s9xfRAoGAbBRyavOfTAgFw7f/bh4K\r\n"
"cOGBThabohzNMQwQ2MIQeU7w0l6ZrC5x7JudrLeuj9M6RLhpugdMKv0Dw8Kxd/Xh\r\n"
"ei2z2Z4DhtgG9QPwZmqkIDZm+TtVndEux1rmYsGipOfenW4JUqjnfjQ959xG47jR\r\n"
"pvMiVsO+fIjI129PovAoRZUCgYEAzGsS55Y+sn674VV2kzEGMR8+bsHzJWk+RAVq\r\n"
"f4j/C+XkqurRA6I/aGJCCwnzBMxbgda/bsF3UJrpxQhQRIOOphS02CB6D/q/9Ge5\r\n"
"nwufnAxksu0eP8nqwx0qGBjeWpNqJH15vBqTO41/HynjEUMD837u9YqW5h99RIU2\r\n"
"Zl7tDvECgYBXNYnE9JoshZSGdWk4rJqZqO7O5PC6nrmLPoEGS6vQh3wrt1UbSG2b\r\n"
"v6uirpo5znf5AyM80zWe+CJl+miaUEv7BQU0+D39nbzTOSdX5UawYJaWY6hwDJAu\r\n"
"VqfOq4DpyJB/ozfJyiakZXVSV87S4zd9b4b7UiFGWKAu1anVX+hbKw==\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

const size_t mbedtls_test_srv_key_rsa_len = sizeof( mbedtls_test_srv_key_rsa );

/* tests/data_files/cli-rsa-sha256.crt */
const char mbedtls_test_cli_crt_rsa[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDEzCCAfugAwIBAgIUIVbJxJATEG//QfkXw1S1tyuvvWUwDQYJKoZIhvcNAQEL\r\n"
"BQAwPDELMAkGA1UEBhMCS1IxFjAUBgNVBAoMDUlDVEsgSG9sZGluZ3MxFTATBgNV\r\n"
"BAMMDDE5Mi4xNjguMS43NzAeFw0xOTA0MjQwMTU0MTlaFw0yNDA0MjIwMTU0MTla\r\n"
"MDwxCzAJBgNVBAYTAktSMRYwFAYDVQQKDA1JQ1RLIEhvbGRpbmdzMRUwEwYDVQQD\r\n"
"DAwxOTIuMTY4LjEuNzcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZ\r\n"
"szEr1AVq91Bn2gy2fThteCbclcOOsXX9wxEhYZOxC98bh0jzz/kLoWlm89vNrz1t\r\n"
"OorKiUKCbtvtOhrklBilMYgz42l4NpqAZvRtf0PbH9jdyoR+PeGKONsue2axSvaV\r\n"
"q/PaPbR+4JtEnf640IHPwdtuZ5z6vW+/NsZme+O+3PmN9j8KZ/fZTUHyjeBHPRie\r\n"
"Xif4LAKp2Yp0ODWycl74kn0FVQfhu4bW8n4cn2EFqeeB6a4JGlaHUGZYO17Icwd7\r\n"
"iZ6w/VaBxvwKa5Xo+ZnqfbbGXtrA92/iDUtVmMisngiZ9gpKc1LlK18+KhUcViBG\r\n"
"ZWcPyGOcEy7ikox8ytS5AgMBAAGjDTALMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEL\r\n"
"BQADggEBADdMjZIzfGFwR+AYgcrJIjqrctt9tcjemjMBUorY0vq/6YXZfIn620Tb\r\n"
"guZ9Eq694aqvixwNGII7C4U22ycpLWvu5AKxY5DKOXlY4t4VNk8WscbisGQUpb5x\r\n"
"rDVG8/DGUQnsCdSxguSU6hBbQT5+1Po0Tn+C1L32qjpjw5lPEu7ywnxjY0B13M8B\r\n"
"YNBbm3FJ71ZX1oOZHC1coBKSgkct+tFqR+6RqEy32jwbzQCcpYPExWqKb/zwNjpG\r\n"
"jO00UTRlbWBEFvrbHMFXDznxKiMqS8MtNMG3UMsbN6p9zYtF8avOQw7sPU6JAt4L\r\n"
"GjtJbomqb/RR6uVtBApVpXqcXhz5f9A=\r\n"
"-----END CERTIFICATE-----\r\n";
const size_t mbedtls_test_cli_crt_rsa_len = sizeof( mbedtls_test_cli_crt_rsa );

/* tests/data_files/cli-rsa.key */
const char mbedtls_test_cli_key_rsa[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIIEpAIBAAKCAQEA2bMxK9QFavdQZ9oMtn04bXgm3JXDjrF1/cMRIWGTsQvfG4dI\r\n"
"88/5C6FpZvPbza89bTqKyolCgm7b7Toa5JQYpTGIM+NpeDaagGb0bX9D2x/Y3cqE\r\n"
"fj3hijjbLntmsUr2lavz2j20fuCbRJ3+uNCBz8Hbbmec+r1vvzbGZnvjvtz5jfY/\r\n"
"Cmf32U1B8o3gRz0Ynl4n+CwCqdmKdDg1snJe+JJ9BVUH4buG1vJ+HJ9hBanngemu\r\n"
"CRpWh1BmWDteyHMHe4mesP1Wgcb8CmuV6PmZ6n22xl7awPdv4g1LVZjIrJ4ImfYK\r\n"
"SnNS5StfPioVHFYgRmVnD8hjnBMu4pKMfMrUuQIDAQABAoIBAD5XCPqjAVYrMhQ7\r\n"
"Ja7QVutKH97E6DYhbUdYp7wmZBOr8ZzBdcuTv55r/3Hi3QueZfm0bPAotCoDsujQ\r\n"
"3cic/B25/GXXdmldQYsJcG82pWjHSuPgTWaVM9PQCjvaTILyk4AyuGbDir9WdEAG\r\n"
"+l1UIAgtXDfWZeaLfseD2PaZ/ZK2z27D4jEHmUmcrTqWu1KOkdfn7a840gXPGI+V\r\n"
"mTqO/eb4seZkK1E1s22oL2Etxd4OyMk4jSE7lHe77178dZihVAZD3ASSRr0PedMh\r\n"
"p8SThxUzxTR0D8G46bcMqkLkS9jtdGHXixQoDYN7DkzCu9FL37UNyDtbeOTan7FT\r\n"
"DV88ps0CgYEA7RvPg8XcRqj7DvS+D6/QeQo4VxWXwXprowLFEZgTPquwFUhehyKW\r\n"
"nt3SAeIT7h1t6QK14fLhYUkiVsfqIbAlCFcMHYI20bdSBxAyVG/FbPYkl1d/Ax0o\r\n"
"GqPMqJJy2tYAHS0hweqmk1TZ8epPO9P5A19rZMRadul9hQQze7AG4kcCgYEA6wuD\r\n"
"Kc07I05i4l6mR37wtA+aAGv6SSScQ8GFItGRFjTePxm78jv8bLjenM/ey2X+wxAp\r\n"
"B5rz+s3azv0NQf2muOIrYdR0YdoLqfUdiedgu004lWIrx1sDN52SA3gaAqpAmPme\r\n"
"X+ww2abRYd8kbxLeOX6k0TZppsv9nSftSlxdEP8CgYBVKowbFNLOPpwO/zHViJ0l\r\n"
"HNqnzQW5ZTOMVc5bR3iCJkEVI+1wNKhNX/ey3XWzLbbw3xxdkFQMEazX5u7eMtra\r\n"
"aAnd/4uZQHOiPdsWIR+Ux8TU54SjpbFmADfexNukZwGbeT6K3LIAcZXnIvZa0wS6\r\n"
"hWeZxj2IQM3pHV0wrEWMuQKBgQDEz1L4wZxvJ8es/MwGucgbPaUaDU/5xuoB4hz0\r\n"
"1r3B9mrSM14oqwnmj7X3YCeR8Mmt0+5HK/x3Wb+J6mIbi6T60oa42AjLlqSFn3Uo\r\n"
"b9GThEmI7Db0KsU64HnO5dYBvUVx0jJG56LP3NseNJZxWz8wrVacyA8XV1/5I+GR\r\n"
"jl1vSQKBgQDDbARDnJ7T29+eKf7ucVhBckKsddrNzpF+MCSGUT9FGSh/tG0+ztuf\r\n"
"+SZ271dYrKCaGbW/t0L9sCr3pSG+SLI+gRfvd+5BRgmVeaZSEWu0x/v5ch8Zp0ZE\r\n"
"Fws49qGYfOft5L+BsMwOfvJXiGYmIc3AM5be8QhZkwRbfKhaTSxxTQ==\r\n"
"-----END RSA PRIVATE KEY-----\r\n";
const size_t mbedtls_test_cli_key_rsa_len = sizeof( mbedtls_test_cli_key_rsa );
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_PEM_PARSE_C)
/* Concatenation of all available CA certificates */
const char mbedtls_test_cas_pem[] =
//#ifdef TEST_CA_CRT_RSA_SHA1
//    TEST_CA_CRT_RSA_SHA1
//#endif
#ifdef TEST_CA_CRT_RSA_SHA256
    TEST_CA_CRT_RSA_SHA256
#endif

#ifdef TEST_CA_CRT_EC
    TEST_CA_CRT_EC
#endif
    "";
const size_t mbedtls_test_cas_pem_len = sizeof( mbedtls_test_cas_pem );
#endif

/* List of all available CA certificates */
const char * mbedtls_test_cas[] = {
//#if defined(TEST_CA_CRT_RSA_SHA1)
//    mbedtls_test_ca_crt_rsa_sha1,
//#endif
#if defined(TEST_CA_CRT_RSA_SHA256)
    mbedtls_test_ca_crt_rsa_sha256,
#endif
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_test_ca_crt_ec,
#endif
    NULL
};
const size_t mbedtls_test_cas_len[] = {
//#if defined(TEST_CA_CRT_RSA_SHA1)
//    sizeof( mbedtls_test_ca_crt_rsa_sha1 ),
//#endif
#if defined(TEST_CA_CRT_RSA_SHA256)
    sizeof( mbedtls_test_ca_crt_rsa_sha256 ),
#endif
#if defined(MBEDTLS_ECDSA_C)
    sizeof( mbedtls_test_ca_crt_ec ),
#endif
    0
};
#endif

#undef MBEDTLS_RSA_C
#if defined(MBEDTLS_RSA_C)
const char *mbedtls_test_ca_crt  = mbedtls_test_ca_crt_rsa; /* SHA1 or SHA256 */
const char *mbedtls_test_ca_key  = mbedtls_test_ca_key_rsa;
const char *mbedtls_test_ca_pwd  = mbedtls_test_ca_pwd_rsa;
const char *mbedtls_test_srv_crt = mbedtls_test_srv_crt_rsa;
const char *mbedtls_test_srv_key = mbedtls_test_srv_key_rsa;
const char *mbedtls_test_cli_crt = mbedtls_test_cli_crt_rsa;
const char *mbedtls_test_cli_key = mbedtls_test_cli_key_rsa;
const size_t mbedtls_test_ca_crt_len  = sizeof( mbedtls_test_ca_crt_rsa );
const size_t mbedtls_test_ca_key_len  = sizeof( mbedtls_test_ca_key_rsa );
const size_t mbedtls_test_ca_pwd_len  = sizeof( mbedtls_test_ca_pwd_rsa ) - 1;
const size_t mbedtls_test_srv_crt_len = sizeof( mbedtls_test_srv_crt_rsa );
const size_t mbedtls_test_srv_key_len = sizeof( mbedtls_test_srv_key_rsa );
const size_t mbedtls_test_cli_crt_len = sizeof( mbedtls_test_cli_crt_rsa );
const size_t mbedtls_test_cli_key_len = sizeof( mbedtls_test_cli_key_rsa );
#else /* ! MBEDTLS_RSA_C, so MBEDTLS_ECDSA_C */
const char *mbedtls_test_ca_crt  = mbedtls_test_ca_crt_ec;
const char *mbedtls_test_ca_key  = mbedtls_test_ca_key_ec;
const char *mbedtls_test_ca_pwd  = mbedtls_test_ca_pwd_ec;
const char *mbedtls_test_srv_crt = mbedtls_test_srv_crt_ec;
const char *mbedtls_test_srv_key = mbedtls_test_srv_key_ec;
const char *mbedtls_test_cli_crt = mbedtls_test_cli_crt_ec;
const char *mbedtls_test_cli_key = mbedtls_test_cli_key_ec;
const size_t mbedtls_test_ca_crt_len  = sizeof( mbedtls_test_ca_crt_ec );
const size_t mbedtls_test_ca_key_len  = sizeof( mbedtls_test_ca_key_ec );
const size_t mbedtls_test_ca_pwd_len  = sizeof( mbedtls_test_ca_pwd_ec ) - 1;
const size_t mbedtls_test_srv_crt_len = sizeof( mbedtls_test_srv_crt_ec );
const size_t mbedtls_test_srv_key_len = sizeof( mbedtls_test_srv_key_ec );
const size_t mbedtls_test_cli_crt_len = sizeof( mbedtls_test_cli_crt_ec );
const size_t mbedtls_test_cli_key_len = sizeof( mbedtls_test_cli_key_ec );
#endif /* MBEDTLS_RSA_C */
#endif
#endif /* MBEDTLS_CERTS_C */

