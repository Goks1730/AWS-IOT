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
```


```http
   /* Initialize credentials for establishing TLS session. */
```

| Parameter | Description                |
| :-------- | :------------------------- |
| `ROOT_CA_CERT_PATH` |  opensslCredentials.pRootCaPath = ROOT_CA_CERT_PATH; |
| `CLIENT_CERT_PATH` |  opensslCredentials.pClientCertPath = CLIENT_CERT_PATH; |
| `CLIENT_PRIVATE_KEY_PATH` |  opensslCredentials.pPrivateKeyPath = CLIENT_PRIVATE_KEY_PATH; |
| `AWS_IOT_ENDPOINT` |  opensslCredentials.sniHostName = AWS_IOT_ENDPOINT;|





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

```javascript
During the ClientKeyExchange step, the client extracts the public key from the verified certificate and generates a new random sequence called the premaster secret. The premaster secret is then encrypted using the extracted public key and is sent to the server. Te SSL/TLS server decrypts the premaster secret using its private key.

Both the client and the server now use the premaster secret to configure a shared secret key. Next, the client sends an encrypted “finished” message using the shared secret key. This message says that the client’s part of the handshake is complete.
```
<img width="926" alt="process" src="https://github.com/Goks1730/AWS-IOT/assets/84590536/75f53cb8-c39f-4ffc-8733-ac02759d612b">
<img width="929" alt="handshake" src="https://github.com/Goks1730/AWS-IOT/assets/84590536/24c67b74-2494-4d63-a68b-9eb7c9c52d0c">

```javascript
Step 8: Finally, an encrypted “finished” message is sent back to the client from the server using the previously agreed shared secret key, which indicates the end of the server’s side of the handshake.
Step 9: Once the SSL/TLS handshake and negotiation is done, the server and the client communication continues, i.e., they begin to share files and messages using the session keys (symmetric encryption).
```
<img width="721" alt="ency data" src="https://github.com/Goks1730/AWS-IOT/assets/84590536/ddcb2d9b-4362-4562-b243-1dadd41e3b9d">
<img width="888" alt="done" src="https://github.com/Goks1730/AWS-IOT/assets/84590536/47e39362-f48b-4855-b5c3-f3bdf3f1bd74">


## certificate signing request (CSR)
```javascript

/**
 * @brief Creates the request payload to be published to the
 * CreateCertificateFromCsr API in order to request a certificate from AWS IoT
 * for the included Certificate Signing Request (CSR).
 *
 * @param[in] pBuffer Buffer into which to write the publish request payload.
 * @param[in] bufferLength Length of #pBuffer.
 * @param[in] pCsr The CSR to include in the request payload.
 * @param[in] csrLength The length of #pCsr.
 * @param[out] pOutLengthWritten The length of the publish request payload.
 */
bool generateCsrRequest( uint8_t * pBuffer,
                         size_t bufferLength,
                         const char * pCsr,
                         size_t csrLength,
                         size_t * pOutLengthWritten );
                         
  * This demo provisions a device certificate using the provisioning by claim
 * workflow with a Certificate Signing Request (CSR). The demo connects to AWS
 * IoT Core using provided claim credentials (whose certificate needs to be
 * registered with IoT Core before running this demo), subscribes to the
 * CreateCertificateFromCsr topics, and obtains a certificate. It then
 * subscribes to the RegisterThing topics and activates the certificate and
 * obtains a Thing using the provisioning template. Finally, it reconnects to
 * AWS IoT Core using the new credentials.
 */
 
      /**** Call the CreateCertificateFromCsr API ***************************/

        /* We use the CreateCertificatefromCsr API to obtain a client certificate
         * for a key on the device by means of sending a certificate signing
         * request (CSR). */
        if( status == true )
        {
            /* Subscribe to the CreateCertificateFromCsr accepted and rejected
             * topics. In this demo we use CBOR encoding for the payloads,
             * so we use the CBOR variants of the topics. */
            status = subscribeToCsrResponseTopics();
        }

        if( status == true )
        {
            /* Create a new key and CSR. */
            status = generateKeyAndCsr( p11Session,
                                        pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                        pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                        csr,
                                        CSR_BUFFER_LENGTH,
                                        &csrLength );
        }

        if( status == true )
        {
            /* Create the request payload containing the CSR to publish to the
             * CreateCertificateFromCsr APIs. */
            status = generateCsrRequest( payloadBuffer,
                                         NETWORK_BUFFER_SIZE,
                                         csr,
                                         csrLength,
                                         &payloadLength );
        }

        if( status == true )
        {
            /* Publish the CSR to the CreateCertificatefromCsr API. */
            status = PublishToTopic( FP_CBOR_CREATE_CERT_PUBLISH_TOPIC,
                                     FP_CBOR_CREATE_CERT_PUBLISH_LENGTH,
                                     ( char * ) payloadBuffer,
                                     payloadLength );

            if( status == false )
            {
                LogError( ( "Failed to publish to fleet provisioning topic: %.*s.",
                            FP_CBOR_CREATE_CERT_PUBLISH_LENGTH,
                            FP_CBOR_CREATE_CERT_PUBLISH_TOPIC ) );
            }
        }
/**
 * @brief MbedTLS callback for signing using the provisioned private key. Used for
 * signing the CSR.
 *
 * @param[in] pContext Unused.
 * @param[in] mdAlg Unused.
 * @param[in] pHash Data to sign.
 * @param[in] hashLen Length of #pHash.
 * @param[out] pSig The signature
 * @param[out] pSigLen The length of the signature.
 * @param[in] pRng Unused.
 * @param[in] pRngContext Unused.
 */
static int32_t privateKeySigningCallback( void * pContext,
                                          mbedtls_md_type_t mdAlg,
                                          const unsigned char * pHash,
                                          size_t hashLen,
                                          unsigned char * pSig,
                                          size_t * pSigLen,
                                          int ( * pRng )( void *, unsigned char *, size_t ),
                                          void * pRngContext );


 /**
 * @brief Generate a new public-private key pair in the PKCS #11 module, and
 * generate a certificate signing request (CSR) for them.
 *
 * This device-generated private key and CSR can be used with the
 * CreateCertificateFromCsr API of the the Fleet Provisioning feature of AWS IoT
 * Core in order to provision a unique client certificate.
 *
 * @param[in] p11Session The PKCS #11 session to use.
 * @param[in] pPrivKeyLabel PKCS #11 label for the private key.
 * @param[in] pPubKeyLabel PKCS #11 label for the public key.
 * @param[out] pCsrBuffer The buffer to write the CSR to.
 * @param[in] csrBufferLength Length of #pCsrBuffer.
 * @param[out] pOutCsrLength The length of the written CSR.
 *
 * @return True on success.
 */
bool generateKeyAndCsr( CK_SESSION_HANDLE p11Session,
                        const char * pPrivKeyLabel,
                        const char * pPubKeyLabel,
                        char * pCsrBuffer,
                        size_t csrBufferLength,
                        size_t * pOutCsrLength );

/**
 * @brief This function details how to use the PKCS #11 "Sign and Verify" functions to
 * create and interact with digital signatures.
 * The functions described are all defined in
 * https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
 * Please consult the standard for more information regarding these functions.
 *
 * The standard has grouped the functions presented in this demo as:
 * Object Management Functions
 * Signing and MACing Functions
 */
CK_RV PKCS11SignVerifyDemo( void )

 /* Signing variables. */
    /* The ECDSA mechanism will be used to sign the message digest. */
    CK_MECHANISM mechanism = { CKM_ECDSA, NULL, 0 };

/* Signing variables. */
    /* The ECDSA mechanism will be used to sign the message digest. */
    CK_MECHANISM mechanism = { CKM_ECDSA, NULL, 0 };
    /* Initializes the sign operation and sets what mechanism will be used
     * for signing the message digest. Specify what object handle to use for this
     * operation, in this case the private key object handle. */
    if( result == CKR_OK )
    {
        LogInfo( ( "Signing known message: %s",
                   ( char * ) knownMessage ) );

        result = functionList->C_SignInit( session,
                                           &mechanism,
                                           privateKeyHandle );
    }
    
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
    
    *************************** ECDSA Capabilities ***************************/
    if( result == CKR_OK )
    {/
        result = functionList->C_GetMechanismInfo( slotId[ 0 ],
                                                   CKM_ECDSA,
                                                   &MechanismInfo );

        if( 0 != ( CKF_SIGN & MechanismInfo.flags ) )
        {
            LogInfo( ( "This Cryptoki library supports signing messages with"
                       " ECDSA private keys." ) );
        }
        else
        {
            LogInfo( ( "This Cryptoki library does not support signing messages"
                       " with ECDSA private keys." ) );
        }

        if( 0 != ( CKF_VERIFY & MechanismInfo.flags ) )
        {
            LogInfo( ( "This Cryptoki library supports verifying messages with"
                       " ECDSA public keys." ) );
        }
        else
        {
            LogInfo( ( "This Cryptoki library does not support verifying"
                       " messages with ECDSA public keys." ) );
        }
    }
    
   
    | Parameter | Description                |
| :-------- | :------------------------- |
| `Cryptoki` |  API to sign messages | |API|
| Public Key Cryptography Standards. |
| 'PKCS #11` |  Signing And Verifying A Signature | |Which specifies an API, called Cryptoki|
    
    
    

```



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
