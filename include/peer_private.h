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
#define PEER_PASSWORD_MINLEN 5
#define PEER_PASSWORD_MAXLEN 50
#define PEER_MESSAGETYPE_MINLEN 4
#define PEER_MESSAGETYPE_MAXLEN 15
#define PEER_INTERVAL_MS_MAX 3600000

#define PEER_AUTH_TIMEOUT 2000

#define PEER_DISCOVERY_PORT 5772 // free port in IANA DB

#define PEER_DOMAIN_DEFAULT "peer_global"

/**
 * @brief Internal function used by peer_whisper functions
 * 
 * @param self Local instance of peer
 * @param peer UUID of remote peer
 * @param internal_message_type PeerNet internal message type
 * @param message_type Public message type (content for internal messages)
 * @param data Internal/external message data
 * @param data_len Internal/external message data length
 * @return int 
 */
PEER_PRIVATE int peer_whisper_internal(peer_t *self, const char *peer, const char *internal_message_type, const char *message_type, void *data, size_t data_len);

typedef void (*peer_py_callback_t)(char *_Nonnull message_type, size_t message_type_len, char *_Nonnull remote_name, size_t remote_name_len, void *_Nullable remote_data, size_t remote_data_len);

/**
 * @brief Register on_connect callback for peer or all peers.
 * 
 * @param self Local instance of peer.
 * @param peer Remote peer name, or NULL for all peers.
 * @param callback Pointer to function of form {@link peer_py_callback_t}
 * @return int 0 for success, -1 for failure, with self->peer_errno set.
 */
PEER_PRIVATE int peer_py_on_connect(peer_t *self, const char *peer, peer_py_callback_t callback);

/**
 * @brief Disable on_connect callback for peer and message type.
 * 
 * @param self Local instance of peer.
 * @param message_type Type of message.
 * @param peer Name of remote peer.
 * @return int 0 for success, -1 for failure, with self->peer_errno set.
 */
PEER_PRIVATE int peer_py_disable_on_connect(peer_t *self, const char *peer);

/**
 * @brief Register on_disconnect callback for peer or all peers.
 * 
 * @param self Local instance of peer.
 * @param peer Remote peer name, or NULL for all peers.
 * @param callback Pointer to function of form {@link peer_py_callback_t}
 * @return int 0 for success, -1 for failure, with self->peer_errno set.
 */
PEER_PRIVATE int peer_py_on_disconnect(peer_t *self, const char *peer, peer_py_callback_t callback);

/**
 * @brief Disable on_disconnect callback for peer and message type.
 * 
 * @param self Local instance of peer.
 * @param message_type Type of message.
 * @param peer Name of remote peer.
 * @return int 0 for success, -1 for failure, with self->peer_errno set.
 */
PEER_PRIVATE int peer_py_disable_on_disconnect(peer_t *self, const char *peer);

/**
 * @brief Register on_evasive callback for peer.
 * 
 * @param self Local instance of peer.
 * @param peer Remote peer name.
 * @param callback Pointer to function of form {@link peer_py_callback_t}
 * @return int 0 for success, -1 for failure, with self->peer_errno set.
 */
PEER_PRIVATE int peer_py_on_evasive(peer_t *self, const char *peer, peer_py_callback_t callback);

/**
 * @brief Disable on_evasive callback for peer and message type.
 * 
 * @param self Local instance of peer.
 * @param message_type Type of message.
 * @param peer Name of remote peer.
 * @return int 0 for success, -1 for failure, with self->peer_errno set.
 */
PEER_PRIVATE int peer_py_disable_on_evasive(peer_t *self, const char *peer);

/**
 * @brief Register on_silent callback for peer.
 * 
 * @param self Local instance of peer.
 * @param peer Remote peer name.
 * @param callback Pointer to function of form {@link peer_py_callback_t}
 * @return int 0 for success, -1 for failure, with self->peer_errno set.
 */
PEER_PRIVATE int peer_py_on_silent(peer_t *self, const char *peer, peer_py_callback_t callback);

/**
 * @brief Disable on_silent callback for peer and message type.
 * 
 * @param self Local instance of peer.
 * @param message_type Type of message.
 * @param peer Name of remote peer.
 * @return int 0 for success, -1 for failure, with self->peer_errno set.
 */
PEER_PRIVATE int peer_py_disable_on_silent(peer_t *self, const char *peer);

/**
 * @brief Register on_message callback for peer.
 * 
 * @param self Local instance of peer.
 * @param message_type Type of remote message.
 * @param peer Remote peer name.
 * @param callback Pointer to function of form {@link peer_py_callback_t}
 * @return int 0 for success, -1 for failure, with self->peer_errno set.
 */
PEER_PRIVATE int peer_py_on_message(peer_t *self, const char *message_type, const char *peer, peer_py_callback_t callback);

/**
 * @brief Disable on_message callback for peer and message type.
 * 
 * @param self Local instance of peer.
 * @param message_type Type of message.
 * @param peer Name of remote peer.
 * @return int 0 for success, -1 for failure, with self->peer_errno set.
 */
PEER_PRIVATE int peer_py_disable_on_message(peer_t *self, const char *message_type, const char *peer);

/**
 * @brief Get a comma separated map of connected peers (name1:uuid1,name2:uuid2,...)
 * 
 * @param self Local instance of peer
 * @return char * pointer to the string containing the data
 */
PEER_PRIVATE char *peer_py_list_connected(peer_t *self);

/**
 * @brief Destroy local instance of peer
 * 
 * @param ptr Pointer to local instance of peer
 */
PEER_PRIVATE void peer_py_destroy(void **ptr);

#endif // __PEER_PRIVATE_H_INCLUDED__