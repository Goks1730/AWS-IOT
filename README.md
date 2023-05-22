# AWS-IOT


## Demo
In demo_config.h

Defining the endpoint, private key and the certificate.

```javascript

/**
 * @brief Details of the MQTT broker to connect to.
 *
 * @note Your AWS IoT Core endpoint can be found in the AWS IoT console under
 * Settings/Custom Endpoint, or using the describe-endpoint API.
 */
 * #define AWS_IOT_ENDPOINT   "...insert here..."


/**
 * @brief AWS IoT MQTT broker port number.
 *
 * In general, port 8883 is for secured MQTT connections.
 *
 * @note Port 443 requires use of the ALPN TLS extension with the ALPN protocol
 * name. When using port 8883, ALPN is not required.
 */
#ifndef AWS_MQTT_PORT
    #define AWS_MQTT_PORT    ( 8883 )
#endif

/**
 * @brief Path of the file containing the server's root CA certificate.
 *
 * This certificate is used to identify the AWS IoT server and is publicly
 * available. Refer to the AWS documentation available in the link below
 * https://docs.aws.amazon.com/iot/latest/developerguide/server-authentication.html#server-authentication-certs
 *
 * Amazon's root CA certificate is automatically downloaded to the certificates
 * directory from @ref https://www.amazontrust.com/repository/AmazonRootCA1.pem
 * using the CMake build system.
 *
 * @note This certificate should be PEM-encoded.
 * @note This path is relative from the demo binary created. Update
 * ROOT_CA_CERT_PATH to the absolute path if this demo is executed from elsewhere.
 */
#ifndef ROOT_CA_CERT_PATH
    #define ROOT_CA_CERT_PATH    "certificates/AmazonRootCA1.crt"
#endif

/**
 * @brief Path of the file containing the client certificate.
 *
 * Refer to the AWS documentation below for details regarding client
 * authentication.
 * https://docs.aws.amazon.com/iot/latest/developerguide/client-authentication.html
 *
 * @note This certificate should be PEM-encoded.
 */
 * #define CLIENT_CERT_PATH   "...insert here..."


/**
 * @brief Path of the file containing the client's private key.
 *
 * Refer to the AWS documentation below for details regarding client
 * authentication.
 * https://docs.aws.amazon.com/iot/latest/developerguide/client-authentication.html
 *
 * @note This private key should be PEM-encoded.
 */
 * #define CLIENT_PRIVATE_KEY_PATH    "...insert here..."

```

## mqtt_demo_mutual_auth\mqtt_demo_mutual_auth.c

## TLS authenticatION

```javascript
/**
 * AWS IoT Core TLS ALPN definitions for MQTT authentication
 * These configuration settings are required to run the mutual auth demo.
 * Throw compilation error if the below configs are not defined.
 */
#ifndef AWS_IOT_ENDPOINT
    #error "Please define AWS IoT MQTT broker endpoint(AWS_IOT_ENDPOINT) in demo_config.h."
#endif
#ifndef ROOT_CA_CERT_PATH
    #error "Please define path to Root CA certificate of the MQTT broker(ROOT_CA_CERT_PATH) in demo_config.h."
#endif
#ifndef CLIENT_IDENTIFIER
    #error "Please define a unique client identifier, CLIENT_IDENTIFIER, in demo_config.h."
#endif

/* The AWS IoT message broker requires either a set of client certificate/private key
 * or username/password to authenticate the client. */
#ifndef CLIENT_USERNAME
    #ifndef CLIENT_CERT_PATH
        #error "Please define path to client certificate(CLIENT_CERT_PATH) in demo_config.h."
    #endif
    #ifndef CLIENT_PRIVATE_KEY_PATH
        #error "Please define path to client private key(CLIENT_PRIVATE_KEY_PATH) in demo_config.h."
    #endif
#else

/* If a username is defined, a client password also would need to be defined for
 * client authentication. */
    #ifndef CLIENT_PASSWORD
        #error "Please define client password(CLIENT_PASSWORD) in demo_config.h for client authentication based on username/password."
    #endif

/* AWS IoT MQTT broker port needs to be 443 for client authentication based on
 * username/password. */
    #if AWS_MQTT_PORT != 443
        #error "Broker port, AWS_MQTT_PORT, should be defined as 443 in demo_config.h for client authentication based on username/password."
    #endif
#endif /* ifndef CLIENT_USERNAME */
```
## connectToServer

```javascript

/* Initialize information to connect to the MQTT broker. */

    serverInfo.pHostName = AWS_IOT_ENDPOINT;
    serverInfo.hostNameLength = AWS_IOT_ENDPOINT_LENGTH;
    serverInfo.port = AWS_MQTT_PORT;

    /* If #CLIENT_USERNAME is defined, username/password is used for authenticating
     * the client. */
    #ifndef CLIENT_USERNAME
        opensslCredentials.pClientCertPath = CLIENT_CERT_PATH;
        opensslCredentials.pPrivateKeyPath = CLIENT_PRIVATE_KEY_PATH;
    #endif
```
## handshake   

## Wireshark is a network protocol analyzer, or an application that captures packets from a network connection, such as from your computer to your home office or the internet. 

```javascript
The 'client hello' message: The client initiates the handshake by sending a "hello" message to the server. The message will include which TLS version the client supports, the cipher suites supported, and a string of random bytes known as the "client random."
```
<img width="926" alt="client hello" src="https://github.com/Goks1730/AWS-IOT/assets/84590536/202a0ae7-1d06-44b0-9622-bde2c401c19e">

```javascript
The 'server hello' message: In reply to the client hello message, the server sends a message containing the server's SSL certificate, the server's chosen cipher suite, and the "server random
```
<img width="936" alt="server hello" src="https://github.com/Goks1730/AWS-IOT/assets/84590536/e9d89eda-3ac1-4295-9320-1e484bdb7850">

## The client performs authentication by contacting the server’s certificate authority (CA) to validate the web server’s digital certificate. This confirms the authenticity of the web server, thus, establishing trust.

<img width="925" alt="server key exchange" src="https://github.com/Goks1730/AWS-IOT/assets/84590536/15bb34ff-f91b-486d-854a-10f6236a7607">


During the ClientKeyExchange step, the client extracts the public key from the verified certificate and generates a new random sequence called the premaster secret. The premaster secret is then encrypted using the extracted public key and is sent to the server. Te SSL/TLS server decrypts the premaster secret using its private key.

Both the client and the server now use the premaster secret to configure a shared secret key. Next, the client sends an encrypted “finished” message using the shared secret key. This message says that the client’s part of the handshake is complete.







```javascript
    /**
     * @brief Filepaths to certificates and private key that are used when
     * performing the TLS handshake.
     *
     * @note These strings must be NULL-terminated because the OpenSSL API requires them to be.
     */
    const char * pRootCaPath;     /**< @brief Filepath string to the trusted server root CA. */
    const char * pClientCertPath; /**< @brief Filepath string to the client certificate. */
    const char * pPrivateKeyPath; /**< @brief Filepath string to the client certificate's private key. */
} OpensslCredentials_t;

static OpensslStatus_t tlsHandshake( const ServerInfo_t * pServerInfo,
                                     OpensslParams_t * pOpensslParams,
                                     const OpensslCredentials_t * pOpensslCredentials )
{
    OpensslStatus_t returnStatus = OPENSSL_SUCCESS;
    int32_t sslStatus = -1, verifyPeerCertStatus = X509_V_OK;

    /* Validate the hostname against the server's certificate. */
    sslStatus = SSL_set1_host( pOpensslParams->pSsl, pServerInfo->pHostName );

    if( sslStatus != 1 )
    {
        LogError( ( "SSL_set1_host failed to set the hostname to validate." ) );
        returnStatus = OPENSSL_API_ERROR;
    }

    /* Enable SSL peer verification. */
    if( returnStatus == OPENSSL_SUCCESS )
    {
        SSL_set_verify( pOpensslParams->pSsl, SSL_VERIFY_PEER, NULL );

        /* Setup the socket to use for communication. */
        sslStatus =
            SSL_set_fd( pOpensslParams->pSsl, pOpensslParams->socketDescriptor );

        if( sslStatus != 1 )
        {
            LogError( ( "SSL_set_fd failed to set the socket fd to SSL context." ) );
            returnStatus = OPENSSL_API_ERROR;
        }
    }

    /* Perform the TLS handshake. */
    if( returnStatus == OPENSSL_SUCCESS )
    {
        setOptionalConfigurations( pOpensslParams->pSsl, pOpensslCredentials );

        sslStatus = SSL_connect( pOpensslParams->pSsl );

        if( sslStatus != 1 )
        {
            LogError( ( "SSL_connect failed to perform TLS handshake." ) );
            returnStatus = OPENSSL_HANDSHAKE_FAILED;
        }
    }

    /* Verify X509 certificate from peer. */
    if( returnStatus == OPENSSL_SUCCESS )
    {
        verifyPeerCertStatus = ( int32_t ) SSL_get_verify_result( pOpensslParams->pSsl );

        if( verifyPeerCertStatus != X509_V_OK )
        {
            LogError( ( "SSL_get_verify_result failed to verify X509 "
                        "certificate from peer." ) );
            returnStatus = OPENSSL_HANDSHAKE_FAILED;
        }
    }

    return returnStatus;
}
```
```javascript
/* Enable the following cipher modes. */
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CFB
#define MBEDTLS_CIPHER_MODE_CTR

/* Enable the following cipher padding modes. */
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
#define MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
#define MBEDTLS_CIPHER_PADDING_ZEROS

/* Cipher suite configuration. */
#define MBEDTLS_REMOVE_ARC4_CIPHERSUITES
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
```
```javascript
## Encryption and Decryption 
SHA256 Mechanism

/**
 * @brief Length in bytes of hex encoded hash digest.
 */
#define HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH         ( ( ( uint16_t ) 64 ) )

/**
 * @brief Length in bytes of SHA256 hash digest.
 */
#define SHA256_HASH_DIGEST_LENGTH                     ( HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH / 2 )

/**
 * @brief Maximum of all the block sizes of hashing algorithms used in the demo for the
 * calculation of hash digest.
 *
 * @note SHA256 hashing Algorithm is used in the demo for calculating the
 * hash digest and maximum block size for this is 64U.
 */
#define SIGV4_HASH_MAX_BLOCK_LENGTH       64U
/**
 * @brief CryptoInterface provided to SigV4 library for generating the hash digest.
 */
static SigV4CryptoInterface_t cryptoInterface =
{
    .hashInit      = sha256Init,
    .hashUpdate    = sha256Update,
    .hashFinal     = sha256Final,
    .pHashContext  = &hashContext,
    .hashBlockLen  = HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH,
    .hashDigestLen = SHA256_HASH_DIGEST_LENGTH,
};

    /********************************* Verify **********************************/

    /* Verify the signature created by C_Sign. First we will verify that the
     * same Cryptoki library was able to trust itself.
     *
     * C_VerifyInit will begin the verify operation, by specifying what mechanism
     * to use (CKM_ECDSA, the same as the sign operation) and then specifying
     * which public key handle to use.
     */
    if( result == CKR_OK )
    {
        result = functionList->C_VerifyInit( session,
                                             &mechanism,
                                             publicKeyHandle );
    }

    /* Given the signature and it's length, the Cryptoki will use the public key
     * to verify that the signature was created by the corresponding private key.
     * If C_Verify returns CKR_OK, it means that the sender of the message has
     * the same private key as the private key that was used to generate the
     * public key, and we can trust that the message we received was from that
     * sender.
     *
     * Note that we are not using the actual message, but the digest that we
     * created earlier of the message, for the verification.
     */
    if( result == CKR_OK )
    {
        result = functionList->C_Verify( session,
                                         digestResult,
                                         pkcs11SHA256_DIGEST_LENGTH,
                                         signature,
                                         signatureLength );

        if( result == CKR_OK )
        {
            LogInfo( ( "The signature of the digest was verified with the"
                       " public key and can be trusted." ) );
        }
        else
        {
            LogInfo( ( "Unable to verify the signature with the given public"
                       " key, the message cannot be trusted." ) );
        }
    }

    /* Export public key as hex bytes and print the hex representation of the
     * public key.
     *
     * We need to export the public key so that it can be used by a different
     * device to verify messages signed by the private key of the device that
     * generated the key pair.
     *
     * To do this, we will output the hex representation of the public key.
     * Then create an empty text file called "DevicePublicKeyAsciiHex.txt".
     *
     * Copy and paste the hex value of the public key into this text file.
     *
     * Then we will need to convert the text file to binary using the xxd tool.
     *
     * xxd will take a text file that contains hex data and output a binary of
     * the hex in the file. See "$ man xxd" for more information about xxd.
     *
     * Copy the below command into the terminal.
     * "$ xxd -r -ps DevicePublicKeyAsciiHex.txt DevicePublicKeyDer.bin"
     *
     * Now that we have the binary encoding of the public key, we will convert
     * it to PEM using OpenSSL.
     *
     * The following command will create a PEM file of the public key called
     * "public_key.pem"
     *
     * "$ openssl ec -inform der -in DevicePublicKeyDer.bin -pubin -pubout -outform pem -out public_key.pem"
     *
     * Now we can use the extracted public key to verify the signature of the
     * device's private key.
     *
     * WARNING: Running the object generation demo will create a new key pair,
     * and make it necessary to redo these steps!
     *
     */
    if( result == CKR_OK )
    {
        LogInfo( ( "Verifying with public key." ) );
        exportPublicKey( session,
                         publicKeyHandle,
                         &derPublicKey,
                         &derPublicKeyLength );
        writeHexBytesToConsole( "Public Key in Hex Format",
                                derPublicKey,
                                derPublicKeyLength );

        /* exportPublicKey allocates memory which needs to be freed. */
        if( derPublicKey != NULL )
        {
            free( derPublicKey );
        }
    }

    /* Set TLS MFLN if requested. */
    if( pOpensslCredentials->maxFragmentLength > 0U )
    {
        LogDebug( ( "Setting max send fragment length %u.",
                    pOpensslCredentials->maxFragmentLength ) );

        /* Set the maximum send fragment length. */

        /* MISRA Directive 4.6 flags the following line for using basic
         * numerical type long. This directive is suppressed because openssl
         * function #SSL_set_max_send_fragment expects a length argument
         * type of long. */
        /* coverity[misra_c_2012_directive_4_6_violation] */
        sslStatus = ( int32_t ) SSL_set_max_send_fragment(
            pSsl, ( long ) pOpensslCredentials->maxFragmentLength );

        if( sslStatus != 1 )
        {
            LogError( ( "Failed to set max send fragment length %u.",
                        pOpensslCredentials->maxFragmentLength ) );
        }
        else
        {
            readBufferLength = ( int16_t ) pOpensslCredentials->maxFragmentLength +
                               SSL3_RT_MAX_ENCRYPTED_OVERHEAD;

            /* Change the size of the read buffer to match the
             * maximum fragment length + some extra bytes for overhead. */
            SSL_set_default_read_buffer_len( pSsl, ( size_t ) readBufferLength );
        }
    }
```
