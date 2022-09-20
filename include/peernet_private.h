/**
 * @file peernet_private.h
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2022-09-20
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef __PEERNET_PRIVATE_H_INCLUDED__
#define __PEERNET_PRIVATE_H_INCLUDED__


#include "peernet.h"
#include "peernet_library.h"

PEERNET_PRIVATE int peer_whisper_internal(peer_t *self, const char *peer, const char *internal_message_type, const char *message_type, void *data, size_t data_len);

#endif // __PEERNET_PRIVATE_H_INCLUDED__