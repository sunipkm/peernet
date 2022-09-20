/**
 * @file peernet.h
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2022-09-18
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef __PEERNET_H_INCLUDED__
#define __PEERNET_H_INCLUDED__

#include "peernet_library.h"

#ifdef __cplusplus
// extern "C"
// {
#endif

/**
 * @brief PeerNet callback function that is executed on a valid event after registration
 * using peer_on_*() functions.
 * 
 * @param self Local instance of peer.
 * @param message_type Type of the message.
 * @param remote_name Name of the remote peer the event was received from.
 * @param data_local Local data. This pointer is NOT freed.
 * @param data_remote Remote data. This pointer is freed, hence data needs to be copied into a state machine to maintain persistence. This pointer is NULL for 
 */
typedef void (*peernet_callback_t)(peer_t *, const char *, const char *, void * _Nullable, void * _Nullable);

/**
 * @brief Create a new pair of name belonging to a group. If group is set to NULL, the default group ('UNIVERSAL') is used.
 * 
 * @param name Unique peer name in the group. The name is not case sensitive. Alphanumeric characters and _ are the only allowed characters. Max length can be 15 characters.
 * @param group Name of group the peer belongs to. Set it to NULL to use the default "UNIVERSAL" group. Max allowed length is 15 characters.
 * @param encryption Enable/disable endpoint encryption.
 * @return peer_t * An instance of a peer on success, NULL on failure. peernet_errno is set accordingly.
 */
PEERNET_EXPORT peer_t *peer_new(const char *name, const char * _Nullable group, bool encryption);

/**
 * @brief Close connections and destroy an instance of a peer.
 * 
 * @param self_p Pointer to local instance of peer. 
 */
PEERNET_EXPORT void peer_destroy(peer_t **self_p);

/**
 * @brief Register a callback function to be executed on receiving a message of
 * 'message_type' from peer 'peer'.
 * 
 * @param self Local instance of peer.
 * @param message_type Message type string. Not case sensitive. Maximum length 15 characters, only alphanumeric characters and _ are allowed.
 * @param peer Name of the remote peer.
 * @param callback Pointer to the function of form @link{peernet_callback_t}, can be NULL.
 * @param args Pointer to arguments to be sent to the callback function, can be NULL.
 * @return int 0 on success, -1 on error. peernet_errno is set accordingly. 
 */
PEERNET_EXPORT int peer_on_message(peer_t *self, const char *message_type, const char *peer, peernet_callback_t _Nullable callback, void * _Nullable local_args);

/**
 * @brief Disable callbacks for the given message type from the given peer.
 * 
 * @param self Local instance of peer.
 * @param message_type Message type string. Not case sensitive. Maximum length 15 characters, only alphanumeric characters and _ are allowed.
 * @param peer Name of the remote peer.
 * @return int 0 on success, -1 on error. peernet_error is set accordingly. 
 */
PEERNET_EXPORT int peer_disable_on_message(peer_t *self, const char *message_type, const char *peer);

/**
 * @brief Register a callback function to be executed on connection of the named
 * peer, or this peer (on execution of @link{peer_start}()) if the name is NULL.
 * Note: If peer is NULL and @link{peer_start}() has already been executed, the
 * callback function has no effect.
 * 
 * @param self Local instance of peer.
 * @param peer Name of the remote peer. Set to NULL for local peer.
 * @param callback Poiner to the function of the form @link{peernet_callback_t}.
 * @param args Pointer to the arguments to be sent to the callback function.
 * @return int 0 on success, -1 on error. peernet_error is set accordingly. 
 */
PEERNET_EXPORT int peer_on_connect(peer_t *self, const char *peer, peernet_callback_t _Nullable callback, void * _Nullable local_args);

/**
 * @brief Disable an already registered callback function supposed to be executed
 * on connection of the named peer, or this peer.
 * 
 * @param self Local instance of peer.
 * @param peer Name of the remote peer, NULL for local peer.
 * @return int 0 on success, -1 on error. peernet_error is set accordingly.
 */
PEERNET_EXPORT int peer_disable_on_connect(peer_t *self, const char * _Nullable peer);

/**
 * @brief Register a callback function to be executed on disconnection of the 
 * named peer, or this peer (on execution of @link{peer_stop}()) if the name is 
 * NULL.
 * Note: If peer is NULL and @link{peer_stop}() has already been executed, the
 * callback function has no effect.
 * 
 * @param self Local instance of peer.
 * @param peer Name of the remote peer, or NULL for local peer.
 * @param callback Poiner to the function of the form @link{peernet_callback_t}.
 * @param args Pointer to the arguments to be sent to the callback function.
 * @return int 0 on success, -1 on error. peernet_error is set accordingly. 
 */
PEERNET_EXPORT int peer_on_disconnect(peer_t *self, const char * _Nullable peer, peernet_callback_t _Nullable callback, void *local_args);

/**
 * @brief Disable an already registered callback function supposed to be executed
 * on disconnection of the named peer, or this peer.
 * 
 * @param self Local instance of peer.
 * @param peer Name of the remote peer, NULL for local peer.
 * @return int 0 on success, -1 on error. peernet_error is set accordingly.
 */
int peer_disable_on_disconnect(peer_t *self, const char * _Nullable peer);

/**
 * @brief Get error string corresponding to peernet errno.
 * 
 * @param error_code Peernet error code.
 * @return const char * String containing error message.
 */
PEERNET_EXPORT const char *peernet_strerror(int error_code);

/**
 * @brief Returns the unique ID of the local peer.
 * 
 * @param self Local instance of peer.
 * @return const char* String containing the unique ID of the peer.
 */
PEERNET_EXPORT const char *peer_uuid(peer_t *self);

/**
 * @brief Returns the name of the local peer.
 * 
 * @param self Local instance of peer.
 * @return const char* String containing the unique name of the peer.
 */
PEERNET_EXPORT const char *peer_name(peer_t *self);

/**
 * @brief Set verbosity of peer communications.
 * 
 * @param self Local instance of peer.
 * @return PEERNET_EXPORT 
 */
PEERNET_EXPORT void peer_set_verbose(peer_t *self);

/**
 * @brief Set UDP beacon discovery port; defaults to 5772. This call overrides
 * that so that independent clusters of peers with the same name and groups 
 * can be created on the same network, e.g. for testing development vs. production
 * codes. Has no effect after @link{peer_start}().
 * 
 * @param self Local instance of peer.
 * @param port Port number. 
 * 
 * @return int 0 on success, -1 on failure. peernet_errno is set to indicate error.
 */
PEERNET_EXPORT int peer_set_port(peer_t *self, int port);

/**
 * @brief Set the peer evasiveness timeout, in milliseconds. Default is 5000.
 * This can be tuned in order to deal with expected network conditions and the
 * response time expected by the application. This is tied to the beacon interval
 * and rate of messages received.
 * 
 * @param self Local instance of peer.
 * @param interval_ms Evasiveness timeout in milliseconds. 
 */
PEERNET_EXPORT int peer_set_evasive_timeout(peer_t *self, unsigned int interval_ms);

/**
 * @brief Set the peer silence timeout, in milliseconds. Default is 5000.
 * This can be tuned in order to deal with expected network conditions and the
 * response time expected by the application. This is tied to the beacon interval
 * and rate of messages received.
 * Silence is triggered one second after the timeout if the peer has not answered
 * ping and has not sent any message.
 * Note: This is currently redundant with the evasiveness timeout. Both affect the
 * same timeout value.
 * 
 * @param self Local instance of peer.
 * @param interval_ms Evasiveness timeout in milliseconds. 
 * 
 * @return int 0 on success, -1 on error.
 */
PEERNET_EXPORT int peer_set_silent_timeout(peer_t *self, unsigned int interval_ms);

/**
 * @brief Set the peer expiration timeout, in milliseconds. Default is 30000.
 * This can be tuned in order to deal with expected network conditions and the
 * response time expected by the application. This is tied to the beacon
 * interval and the rate of messages received.
 * 
 * @param self Local instance of peer.
 * @param interval_ms Evasiveness timeout in milliseconds.
 * 
 * @return int 0 on success, -1 on error.
 */
PEERNET_EXPORT int peer_set_expired_timeout(peer_t *self, unsigned int interval_ms);

/**
 * @brief Set UDP beacon discovery interval, in milliseconds. Default is instant beacon
 * exploration followed by pinging every 1,000 ms.
 * 
 * @param self Local instance of peer.
 * @param interval_ms Evasiveness timeout in milliseconds.
 * 
 * @return int 0 on success, -1 on error. 
 */
PEERNET_EXPORT int peer_set_interval(peer_t *self, size_t interval_ms);

/**
 * @brief Set the network interface for UDP beacons. If you do not set this, CZMQ
 * will choose an interface for you. On boxes with several interfaces, the interface
 * should be specified or connection issues may occur.
 * The interface may be specified either by the interface name (e.g. "eth0") or
 * an IP address associated with the interface (e.g. "192.168.0.1").
 * 
 * @param self Local instance of peer.
 * @param value Interface name or local IP address on the interface. 
 */
PEERNET_EXPORT void peer_set_interface(peer_t *self, const char *value);

/**
 * @brief By default, PeerNet binds to an ephemeral TCP port and broadcasts the 
 * local host name using UDP beacons. When this method is called, PeerNet will 
 * use gossip discovery instead of UDP beacons. The gossip service MUST BE set 
 * up separately using @link{peer_gossip_bind}() and @link{peer_gossip_connect}().
 * Note that, the endpoint MUST be valid for both bind and connect operations. 
 * inproc://, ipc://, or tcp:// transports (for tcp://, use an IP address that is
 * meaningful to remote as well as local peers). Returns 0 if the bind was 
 * successful, -1 otherwise.
 * 
 */
PEERNET_EXPORT int peer_set_endpoint(peer_t *self, const char *format, ...) CHECK_PRINTF(2);

/**
 * @brief Set up gossip discovery of other peers. At least one peer in the cluster
 * must bind to a well-known gossip endpoint, so that other peers can connect to it.
 * Note that, gossip endpoints are completely distinct from PeerNet node endpoints,
 * and should not overlap (they can use the same transport). For details of the
 * gossip network design, see the CZMQ zgossip class.
 * 
 * @param format Format string, followed by inputs. 
 */
PEERNET_EXPORT void peer_gossip_bind(peer_t *self, const char *format, ...) CHECK_PRINTF(2);

/**
 * @brief Set up gossip discovery of other peers. A peer may connect to multiple other
 * peers, for redundancy paths. For details of the gossip network design, see the CZMQ
 * zgossip class.
 * 
 * @param format Format string, followed by inputs.
 */
PEERNET_EXPORT void peer_gossip_connect(peer_t *self, const char *format, ...) CHECK_PRINTF(2);

/**
 * @brief Start the peer, after setting the header values. A peer starts discovery and
 * connection beyond this point. Returns 0 if success, and -1 on failure.
 * 
 * @param self Local instance of peer.
 * @return int 0 on success, -1 on error. 
 */
PEERNET_EXPORT int peer_start(peer_t *self);

/**
 * @brief Stop the peer. This signals to the other peers that this peer will go away.
 * This is polite; however the node can be destroyed without stopping.
 * 
 * @param self Local instance of peer. 
 */
PEERNET_EXPORT void peer_stop(peer_t *self);

/**
 * @brief Send (whisper) a message to a single peer on the network. Destroys
 * the message after sending.
 * 
 * @param self Local instance of peer.
 * @param name Name of the remote peer.
 * @param message_type String describing the type of the message.
 * @param data Pointer to data
 * @param data_len Length of the memory pointed to by data
 * @return int Returns 0 on success, -1 on failure.
 */
PEERNET_EXPORT int peer_whisper(peer_t *self, const char *name, const char *message_type, void *data, size_t data_len);

/**
 * @brief Send (whisper) a formatted string to a single peer on the network.
 * 
 * @param self Local instance of peer.
 * @param name Name of the remote peer.
 * @param message_type String describing the type of the message.
 * 
 * @param format Format string for the message.
 */
PEERNET_EXPORT int peer_whispers(peer_t *self, const char *name, const char *message_type, const char *format, ...) CHECK_PRINTF(4);

/**
 * @brief Send (shout) a message to all peers on the network. Destroys
 * the message after sending.
 * 
 * @param self Local instance of peer.
 * @param message_type String describing the type of the message.
 * @param data Pointer to data
 * @param data_len Length of the memory pointed to by data
 * @return int Returns 0 on success, -1 on failure.
 */
PEERNET_EXPORT int peer_shout(peer_t *self, const char *message_type, void *data, size_t data_len);

/**
 * @brief Send (shout) a formatted string to all peers on the network.
 * 
 * @param self Local instance of peer.
 * @param name Name of the remote peer.
 * @param message_type String describing the type of the message.
 * 
 * @param format Format string for the message.
 */
PEERNET_EXPORT int peer_shouts(peer_t *self, const char *message_type, const char *format, ...) CHECK_PRINTF(3);

/**
 * @brief Return a list of peers this peer (in the same group) is connected to.
 * 
 * @param self Local instance of peer.
 * @return zhash_t * List of peers  
 */
PEERNET_EXPORT zhash_t *peernet_peers(peer_t *self);

/**
 * @brief Return the endpoint of a connected peer.
 * 
 * @param self Local instance of peer.
 * @param name Remote peer name.
 * @return char* Remote peer address, caller owns the object and must free it when done.
 */
PEERNET_EXPORT char *peernet_peer_address(peer_t *self, const char *name);

/**
 * @brief Return the value of a header of a connected peer.
 * 
 * @param self Local instance of peer.
 * @param name Remote peer name.
 * @return char* Returns NULL if peer or key does not exist, caller owns the object and must free it when done.
 */
PEERNET_EXPORT char *peernet_peer_header_value(peer_t *self, const char *name);

/**
 * @brief Print information about this peer.
 * 
 * @param self Local instance of peer.
 */
PEERNET_EXPORT void peer_print(peer_t *self);

/**
 * @brief Return the PeerNet version for the run-time API detection.
 * 
 * @return uint64_t major * 10000 + minor * 100 + patch, as a single integer. 
 */
PEERNET_EXPORT uint64_t peernet_version(void);

/**
 * @brief Self-test of the peer_t class.
 * 
 * @param verbose Enable verbosity.
 */
PEERNET_EXPORT void peer_test(bool verbose);

/**
 * @brief Get the zyre_t class instance providing backend connectivity
 * to the local instance of the peer class.
 * 
 * @param self Local instance of peer.
 * @return zyre_t * Class instance providing backend connectivity.
 */
PEERNET_EXPORT zyre_t *peer_get_backend(peer_t *self);

typedef enum
{
    PEERNET_SUCCESS = 0, /*!< Operation was successful. */
    PEERNET_PEER_EXISTS = 1,
    PEERNET_PEER_NAME_LENGTH_INVALID = 2,
    PEERNET_PEER_NAME_INVALID_CHARS = 3,
    PEERNET_PEER_GROUP_LENGTH_INVALID = 4,
    PEERNET_PEER_GROUP_INVALID_CHARS = 5,
    PEERNET_PEER_NODE_CREATE_FAILED = 6,
    PEERNET_PEER_GROUP_HASH_FAILED = 7,
    PEERNET_PORT_RANGE_INVALID = 8,
    PEERNET_INTERVAL_TOO_LARGE = 9,
    PEERNET_STRDUP_FAILED = 10,
    PEERNET_ZMSG_NEW_FAILED = 11,
    PEERNET_ZMSG_STR_INSERT_FAILED = 12,
    PEERNET_ZMSG_MEM_INSERT_FAILED = 13,
    PEERNET_NAME_IS_NULL = 14,
    PEERNET_MESSAGETYPE_IS_NULL = 15,
    PEERNET_MESSAGETYPE_LENGTH_INVALID = 16,
    PEERNET_MESSAGETYPE_INVALID_CHARS = 17,
    PEERNET_MESSAGE_PAYLOAD_NULL = 18,
    PEERNET_MESSAGE_PAYLOAD_LENGTH_ZERO = 19,
    PEERNET_DESTINATION_PEER_NOT_FOUND = 20,
    PEERNET_FORMAT_STR_IS_NULL = 21,
    PEERNET_PEER_NODE_START_FAILED = 22,
    PEERNET_PEER_NODE_GROUP_JOIN_FAILED = 23,
    PEERNET_COULD_NOT_SIGNAL_PIPE = 24,
    PEERNET_COULD_NOT_CREATE_ZPOLLER = 25,
    PEERNET_PEER_SELF_INSERTION_FAILED = 26,
    PEERNET_CALLBACK_DRIVER_FAILED = 27,
    PEERNET_MESSAGE_TYPE_REGISTRATION_FAILED = 28,
    PEERNET_CALLBACK_INSERTION_FAILED = 29,
    PEERNET_CALLBACK_LOCALARG_INSERTION_FAILED = 30,
    PEERNET_CALLBACK_LIST_CREATION_FAILED = 31,
    PEERNET_CALLBACK_ARG_LIST_CREATION_FAILED = 32,
    PEENRET_CALLBACK_TABLE_INSERTION_FAILED = 33,
    PEENRET_CALLBACK_ARGS_TABLE_INSERTION_FAILED = 34,
    PEERNET_GROUP_IS_NULL = 35,
    PEERNET_ZYRE_WHISPER_FAILED = 36,
    PEERNET_ZYRE_WHISPERS_FAILED = 37,
    PEERNET_ZYRE_SHOUT_FAILED = 38,
    PEERNET_ZYRE_SHOUTS_FAILED = 39,
    PEERNET_ZYRE_PEER_ADDRESS_NOT_FOUND = 40,
    PEERNET_ZYRE_PEER_HEADER_VALUE_FAILED = 41,
    PEERNET_MESSAGE_TYPE_NOT_REGISTERED = 42,
    PEERNET_CALLBACK_DOES_NOT_EXIST = 43,
    PEERNET_STRCONCAT_FAILED = 44,
    PEERNET_RECEIVER_FAILED = 45,
    PEERNET_MAX_ERROR
} PEERNET_ERRORS;
#ifdef __cplusplus
// }
#endif

#endif