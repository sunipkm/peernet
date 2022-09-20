/**
 * @file peer_private.h
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2022-09-20
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef __PEER_PRIVATE_H_INCLUDED__
#define __PEER_PRIVATE_H_INCLUDED__


#include "peer.h"
#include "peer_library.h"

#define PEER_NAME_MINLEN 4
#define PEER_NAME_MAXLEN 15
#define PEER_GROUP_MINLEN 4
#define PEER_GROUP_MAXLEN 15
#define PEER_MESSAGETYPE_MINLEN 4
#define PEER_MESSAGETYPE_MAXLEN 15
#define PEER_INTERVAL_MS_MAX 3600000

#define PEER_DISCOVERY_PORT 5772 // free port in IANA DB

#define PEER_DOMAIN_DEFAULT "peer_global"

PEER_PRIVATE int peer_whisper_internal(peer_t *self, const char *peer, const char *internal_message_type, const char *message_type, void *data, size_t data_len);

#endif // __PEER_PRIVATE_H_INCLUDED__