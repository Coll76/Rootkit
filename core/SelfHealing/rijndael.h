#ifndef RIJNDAEL_H
#define RIJNDAEL_H

// Enumeration for AES cipher modes
typedef enum {
    AES_CYPHER_128,
    AES_CYPHER_192,
    AES_CYPHER_256,
} AES_CYPHER_T;

// Include standard integer types if not included
#ifdef _MSC_VER
    #if _MSC_VER >= 1600
        #include <stdint.h>
    #else
        typedef __int8              int8_t;
        typedef __int16             int16_t;
        typedef __int32             int32_t;
        typedef __int64             int64_t;
        typedef unsigned __int8     uint8_t;
        typedef unsigned __int16    uint16_t;
        typedef unsigned __int32    uint32_t;
        typedef unsigned __int64    uint64_t;
    #endif
#elif defined(__GNUC__) && __GNUC__ >= 3
    #include <stdint.h>
#else
    // Provide default typedefs if needed
    typedef signed char          int8_t;
    typedef signed short         int16_t;
    typedef signed int           int32_t;
    typedef signed long long     int64_t;
    typedef unsigned char        uint8_t;
    typedef unsigned short       uint16_t;
    typedef unsigned int         uint32_t;
    typedef unsigned long long   uint64_t;
#endif

// Function declarations for AES encryption and decryption
int aes_encrypt_ecb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key);
int aes_decrypt_ecb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key);
int aes_encrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv);
int aes_decrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv);

#endif // RIJNDAEL_H
