/*
 * network_types.h
 *
 *  Created on: Jul 21, 2017
 */

#ifndef NETWORK_NETWORK_TYPES_H_
#define NETWORK_NETWORK_TYPES_H_

#include <stdint.h>

#define NETWORK_DH_REQUEST      0x00
#define NETWORK_DH_MESSAGE_1    0x01
#define NETWORK_DH_MESSAGE_2    0x02
#define NETWORK_DH_MESSAGE_3    0x03
#define NETWORK_MESSAGE         0x04

/* Used to send a message that contains an unencrypted part for the untrusted app */
#define NETWORK_NESTED_MESSAGE  0x05

#define NETWORK_MESSAGE_RESPONSE 0x06

#define NETWORK_RA_MESSAGE_QUOTE  0x10

#define NETWORK_SHUTDOWN        0xE0
#define NETWORK_ERROR_UNKNOWN_ERROR 0xF0
#define NETWORK_ERROR_UNKNOWN_TYPE 0xF1

#define MESSAGE_HEADER_SIZE 4

// message
typedef struct _message {
    uint32_t size_encrypted;
    uint32_t size_plaintext;
    uint32_t type;
    uint32_t session_id;
    void* data_encrypted;
    void* data_plaintext;
} message_t;



#endif /* NETWORK_NETWORK_TYPES_H_ */
