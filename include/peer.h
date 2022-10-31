/**
 * @file peer.h
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief Peer to peer networking library with local peer discovery around CZMQ.
 * @version See documentation.
 * @date 2022-09-18
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef __PEER_H_INCLUDED__
#define __PEER_H_INCLUDED__

#include "peer_library.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if !defined(_Nullable)
/**
 * @brief Indicates the pointer argument can be NULL.
 *
 */
#define _Nullable
#endif

#if !defined(_Nonnull)
/**
 * @brief Indicates the pointer argument can not be NULL.
 *
 */
#define _Nonnull
#endif

/**
 * @brief PeerNet callback function that is executed on a valid event after registration
 * using peer_on_*() functions.
 *
 * @param self Local instance of peer.
 * @param message_type Type of the message.
 * @param remote_name Name of the remote peer the event was received from.
 * @param local_data Local data. This pointer is NOT freed.
 * @param remote_data Remote data. THIS POINTER IS NOT OWNED BY THE CALLBACK FUNCTION. This pointer is freed, hence data needs to be copied into a state machine to maintain persistence. This pointer is NULL for connect or disconnect callbacks.
 * @param remote_data_len Length of the remote data.
 */
typedef void (*peer_callback_t)(peer_t *_Nonnull self, const char *_Nonnull message_type, const char *_Nonnull remote_name, void *_Nullable local_data, void *_Nullable remote_data, size_t remote_data_len);

/**
 * @brief Create a new pair of name belonging to a group. If group is set to NULL, the default group ('UNIVERSAL') is used.
 *
 * Note: Instead of handling SIGINT in your code, use the zsys_interrupted variable.
 *
 * @param name Unique peer name in the group. The name is not case sensitive. Alphanumeric characters and _ are the only allowed characters. Length has to be between 4 and 15 characters (inclusive).
 * @param group Name of group the peer belongs to. Set it to NULL to use the default "UNIVERSAL" group. Length has to be between 4 and 15 characters (inclusive).
 * @param password Plaintext password, only alphanumeric characters and '_' are allowed. Length has to be between 4 and 50 characters (inclusive). Password IS case sensitive.
 * @param encryption Enable/disable endpoint encryption.
 * @return peer_t * An instance of a peer on success, NULL on failure. errno is set accordingly. Use {@link peer_strerror}() to get the corresponding error string.
 */
PEER_EXPORT peer_t *peer_new(const char *_Nonnull name, const char *_Nullable group, const char *_Nonnull password, bool encryption);

/**
 * @brief Close connections and destroy an instance of a peer.
 *
 * @param self_p Pointer to local instance of peer.
 */
PEER_EXPORT void peer_destroy(peer_t **_Nonnull self_p);

/**
 * @brief Register a callback function to be executed on receiving a message of
 * 'message_type' from peer 'peer'.
 *
 * @param self Local instance of peer.
 * @param peer Name of the remote peer.
 * @param message_type Message type string. Not case sensitive. Length has to be between 4 and 15 characters (inclusive), only alphanumeric characters and _ are allowed.
 * @param callback Pointer to the function of form {@link peer_callback_t}, can be NULL.
 * @param local_args Pointer to arguments to be sent to the callback function, can be NULL.
 * @return int 0 on success, negative on error. Human readable error message can be retrieved by passing the return value to {@link peer_strerror}().
 */
PEER_EXPORT int peer_on_message(peer_t *_Nonnull self, const char *_Nonnull peer, const char *_Nonnull message_type, peer_callback_t _Nullable callback, void *_Nullable local_args);

/**
 * @brief Disable callbacks for the given message type from the given peer.
 *
 * @param self Local instance of peer.
 * @param peer Name of the remote peer.
 * @param message_type Message type string.
 * @return int 0 on success, negative on error. Human readable error message can be retrieved by passing the return value to {@link peer_strerror}()..
 */
PEER_EXPORT int peer_disable_on_message(peer_t *_Nonnull self, const char *_Nonnull peer, const char *_Nonnull message_type);

/**
 * @brief Register a callback function to be executed on connection of the named
 * peer, or this peer (on execution of {@link peer_start}) if the name is NULL.
 * Note: If peer is NULL and {@link peer_start} has already been executed, the
 * callback function has no effect.
 *
 * @param self Local instance of peer.
 * @param peer Name of the peer. Set to NULL for any peer.
 * @param callback Poiner to the function of the form {@link peer_callback_t}.
 * @param local_args Pointer to the arguments to be sent to the callback function.
 * @return int 0 on success, negative on error. Human readable error message can be retrieved by passing the return value to {@link peer_strerror}()..
 */
PEER_EXPORT int peer_on_connect(peer_t *_Nonnull self, const char *_Nullable peer, peer_callback_t _Nullable callback, void *_Nullable local_args);

/**
 * @brief Disable an already registered callback function supposed to be executed
 * on connection of the named peer, or this peer.
 *
 * @param self Local instance of peer.
 * @param peer Name of the peer, NULL for any peer.
 * @return int 0 on success, negative on error. Human readable error message can be retrieved by passing the return value to {@link peer_strerror}()..
 */
PEER_EXPORT int peer_disable_on_connect(peer_t *_Nonnull self, const char *_Nullable peer);

/**
 * @brief Register a callback function to be executed on disconnection of the
 * named peer, or this peer (on execution of {@link peer_stop}) if the name is
 * NULL.
 * Note: If peer is NULL and {@link peer_stop} has already been executed, the
 * callback function has no effect.
 *
 * @param self Local instance of peer.
 * @param peer Name of the peer, or NULL for any peer.
 * @param callback Poiner to the function of the form {@link peer_callback_t}.
 * @param local_args Pointer to the arguments to be sent to the callback function.
 * @return int 0 on success, negative on error. Human readable error message can be retrieved by passing the return value to {@link peer_strerror}()..
 */
PEER_EXPORT int peer_on_disconnect(peer_t *_Nonnull self, const char *_Nullable peer, peer_callback_t _Nullable callback, void *_Nullable local_args);

/**
 * @brief Disable an already registered callback function supposed to be executed
 * on disconnection of the named peer, or this peer.
 *
 * @param self Local instance of peer, or NULL for any peer.
 * @param peer Name of the remote peer, NULL for local peer.
 * @return int 0 on success, negative on error. Human readable error message can be retrieved by passing the return value to {@link peer_strerror}()..
 */
PEER_EXPORT int peer_disable_on_disconnect(peer_t *_Nonnull self, const char *_Nullable peer);

/**
 * @brief Register a callback function to be executed on if the peer is being
 * evasive (non-responsive).
 * Note: The callback function should check if the remote peer has already
 * been evicted after exceeding retry count by checking if the peer exists.
 *
 * @param self Local instance of peer.
 * @param peer Name of the remote peer.
 * @param callback Poiner to the function of the form {@link peer_callback_t}.
 * @param local_args Pointer to the arguments to be sent to the callback function.
 * @return int 0 on success, negative on error. Human readable error message can be retrieved by passing the return value to {@link peer_strerror}()..
 */
PEER_EXPORT int peer_on_evasive(peer_t *_Nonnull self, const char *_Nonnull peer, peer_callback_t _Nullable callback, void *_Nullable local_args);

/**
 * @brief Disable an already registered callback function supposed to be executed
 * on evasion of the named peer.
 *
 * @param self Local instance of peer.
 * @param peer Name of remote peer.
 * @return int 0 on success, negative on error. Human readable error message can be retrieved by passing the return value to {@link peer_strerror}()..
 */
PEER_EXPORT int peer_disable_on_evasive(peer_t *_Nonnull self, const char *_Nonnull peer);

/**
 * @brief Register a callback function to be executed on if the peer is being
 * silent (non-responsive).
 * Note: The remote peer has already been evicted at this point.
 *
 * @param self Local instance of peer.
 * @param peer Name of the remote peer.
 * @param callback Poiner to the function of the form {@link peer_callback_t}.
 * @param local_args Pointer to the arguments to be sent to the callback function.
 * @return int 0 on success, negative on error. Human readable error message can be retrieved by passing the return value to {@link peer_strerror}()..
 */
PEER_EXPORT int peer_on_silent(peer_t *_Nonnull self, const char *_Nonnull peer, peer_callback_t _Nullable callback, void *_Nullable local_args);

/**
 * @brief Disable an already registered callback function supposed to be executed
 * on silence of the named peer.
 *
 * @param self Local instance of peer.
 * @param peer Name of remote peer.
 * @return int 0 on success, negative on error. Human readable error message can be retrieved by passing the return value to {@link peer_strerror}()..
 */
PEER_EXPORT int peer_disable_on_silent(peer_t *_Nonnull self, const char *_Nonnull peer);

/**
 * @brief Disable sending eviction request to remote instance of peer on SILENT.
 * This feature is disabled by default.
 *
 * @param self Local instance of peer.
 * @param eviction True to evict other peers when they are silent.
 */
PEER_EXPORT void peer_set_silent_eviction(peer_t *_Nonnull self, bool eviction);

/**
 * @brief Get the current peer eviction policy on "SILENT" message from node.
 *
 * @param self Local instance of peer.
 * @return bool True if enabled, false otherwise.
 */
PEER_EXPORT bool peer_silent_eviction_enabled(peer_t *_Nonnull self);

/**
 * @brief Get error/status messages from the underlying peer receiver.
 *
 * @param self Local instance of peer.
 * @param timeout_ms -1 to wait forever.
 * @return int Status from @{link PEER_ERRORS}.
 */
PEER_EXPORT int peer_get_receiver_messages(peer_t *_Nonnull self, int timeout_ms);

/**
 * @brief Check if the peer exists in the network.
 *
 * @param self Local instance of peer.
 * @param peer Name of remote peer.
 * @return bool
 */
PEER_EXPORT bool peer_exists(peer_t *_Nonnull self, const char *_Nonnull peer);

/**
 * @brief Get error string corresponding to peer errno.
 *
 * @param error_code Peernet error code.
 * @return const char * String containing error message.
 */
PEER_EXPORT const char *peer_strerror(int error_code);

/**
 * @brief Returns the unique ID of the local peer.
 *
 * @param self Local instance of peer.
 * @return const char* String containing the unique ID of the peer.
 */
PEER_EXPORT const char *peer_uuid(peer_t *_Nonnull self);

/**
 * @brief Returns the name of the local peer.
 *
 * @param self Local instance of peer.
 * @return const char* String containing the unique name of the peer.
 */
PEER_EXPORT const char *peer_name(peer_t *_Nonnull self);

/**
 * @brief Set verbosity of peer communications.
 *
 * @param self Local instance of peer.
 */
PEER_EXPORT void peer_set_verbose(peer_t *_Nonnull self);

/**
 * @brief Set UDP beacon discovery port; defaults to 5772. This call overrides
 * that so that independent clusters of peers with the same name and groups
 * can be created on the same network, e.g. for testing development vs. production
 * codes. Has no effect after {@link peer_start}.
 *
 * @param self Local instance of peer.
 * @param port Port number.
 *
 * @return int 0 on success, -1 on failure. peer_errno is set to indicate error.
 */
PEER_EXPORT int peer_set_port(peer_t *_Nonnull self, int port);

/**
 * @brief Set the peer evasiveness timeout, in milliseconds. Default is 5000.
 * This can be tuned in order to deal with expected network conditions and the
 * response time expected by the application. This is tied to the beacon interval
 * and rate of messages received.
 *
 * @param self Local instance of peer.
 * @param interval_ms Evasiveness timeout in milliseconds.
 */
PEER_EXPORT int peer_set_evasive_timeout(peer_t *_Nonnull self, unsigned int interval_ms);

/**
 * @brief Set the number of retries before a non-responsive peer is requested to exit.
 * Default is -1, i.e. remote peer is never booted.
 * Note: This function is non-effective after {@link peer_start} has been called.
 *
 * @param self Local instance of peer.
 * @param retry_count Evasion retry count, should be positive or negative. A value of 0 is treated as -1.
 */
PEER_EXPORT void peer_set_evasive_retry_count(peer_t *self, int retry_count);

/**
 * @brief Set the peer expiration timeout, in milliseconds. Default is 30000.
 * This can be tuned in order to deal with expected network conditions and the
 * response time expected by the application. This is tied to the beacon
 * interval and the rate of messages received.
 *
 * @param self Local instance of peer.
 * @param interval_ms Expiration timeout in milliseconds.
 *
 * @return int 0 on success, -1 on error.
 */
PEER_EXPORT int peer_set_expired_timeout(peer_t *_Nonnull self, unsigned int interval_ms);

/**
 * @brief Set UDP beacon discovery interval, in milliseconds. Default is instant beacon
 * exploration followed by pinging every 1,000 ms.
 *
 * @param self Local instance of peer.
 * @param interval_ms Beacon discovery timeout in milliseconds.
 *
 * @return int 0 on success, -1 on error.
 */
PEER_EXPORT int peer_set_interval(peer_t *_Nonnull self, size_t interval_ms);

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
PEER_EXPORT void peer_set_interface(peer_t *_Nonnull self, const char *_Nonnull value);

/**
 * @brief By default, PeerNet binds to an ephemeral TCP port and broadcasts the
 * local host name using UDP beacons. When this method is called, PeerNet will
 * use gossip discovery instead of UDP beacons. The gossip service MUST BE set
 * up separately using {@link peer_gossip_bind} and {@link peer_gossip_connect}.
 * Note that, the endpoint MUST be valid for both bind and connect operations.
 * inproc://, ipc://, or tcp:// transports (for tcp://, use an IP address that is
 * meaningful to remote as well as local peers). Returns 0 if the bind was
 * successful, -1 otherwise.
 *
 */
PEER_EXPORT int peer_set_endpoint(peer_t *_Nonnull self, const char *_Nonnull format, ...) CHECK_PRINTF(2);

/**
 * @brief Set up gossip discovery of other peers. At least one peer in the cluster
 * must bind to a well-known gossip endpoint, so that other peers can connect to it.
 * Note that, gossip endpoints are completely distinct from PeerNet node endpoints,
 * and should not overlap (they can use the same transport). For details of the
 * gossip network design, see the CZMQ zgossip class.
 *
 * @param self Local instance of peer.
 * @param format Format string, followed by inputs.
 */
PEER_EXPORT void peer_gossip_bind(peer_t *_Nonnull self, const char *_Nonnull format, ...) CHECK_PRINTF(2);

/**
 * @brief Set up gossip discovery of other peers. A peer may connect to multiple other
 * peers, for redundancy paths. For details of the gossip network design, see the CZMQ
 * zgossip class.
 *
 * @param self Local instance of peer.
 * @param format Format string, followed by inputs.
 */
PEER_EXPORT void peer_gossip_connect(peer_t *_Nonnull self, const char *_Nonnull format, ...) CHECK_PRINTF(2);

/**
 * @brief Start the peer, after setting the header values. A peer starts discovery and
 * connection beyond this point. Returns 0 if success, and -1 on failure.
 *
 * @param self Local instance of peer.
 * @return int 0 on success, -1 on error.
 */
PEER_EXPORT int peer_start(peer_t *_Nonnull self);

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
PEER_EXPORT int peer_whisper(peer_t *_Nonnull self, const char *_Nonnull name, const char *_Nonnull message_type, void *_Nonnull data, size_t data_len);

/**
 * @brief Send (whisper) a formatted string to a single peer on the network.
 *
 * @param self Local instance of peer.
 * @param name Name of the remote peer.
 * @param message_type String describing the type of the message.
 *
 * @param format Format string for the message.
 */
PEER_EXPORT int peer_whispers(peer_t *_Nonnull self, const char *_Nonnull name, const char *_Nonnull message_type, const char *_Nonnull format, ...) CHECK_PRINTF(4);

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
PEER_EXPORT int peer_shout(peer_t *_Nonnull self, const char *_Nonnull message_type, void *_Nonnull data, size_t data_len);

/**
 * @brief Send (shout) a formatted string to all peers on the network.
 *
 * @param self Local instance of peer.
 * @param message_type String describing the type of the message.
 *
 * @param format Format string for the message.
 */
PEER_EXPORT int peer_shouts(peer_t *_Nonnull self, const char *_Nonnull message_type, const char *_Nonnull format, ...) CHECK_PRINTF(3);

/**
 * @brief Return a list of peers this peer (in the same group) is connected to.
 *
 * @param self Local instance of peer.
 * @return zhash_t * List of peers
 */
PEER_EXPORT zhash_t *peer_list_connected(peer_t *_Nonnull self);

/**
 * @brief Return the endpoint of a connected peer.
 *
 * @param self Local instance of peer.
 * @param name Remote peer name.
 * @return char* Remote peer address, caller owns the object and must free it when done.
 */
PEER_EXPORT char *peer_get_remote_address(peer_t *_Nonnull self, const char *_Nonnull name);

/**
 * @brief Return the value of a header of a connected peer.
 *
 * @param self Local instance of peer.
 * @param name Remote peer name.
 * @return char* Returns NULL if peer or key does not exist, caller owns the object and must free it when done.
 */
PEER_EXPORT char *peer_get_remote_header_value(peer_t *_Nonnull self, const char *_Nonnull name);

/**
 * @brief Print information about this peer.
 *
 * @param self Local instance of peer.
 */
PEER_EXPORT void peer_print(peer_t *_Nonnull self);

/**
 * @brief Return the PeerNet version for the run-time API detection.
 *
 * @return uint64_t major * 10000 + minor * 100 + patch, as a single integer.
 */
PEER_EXPORT uint64_t peer_version(void);

/**
 * @brief Self-test of the peer_t class.
 *
 * @param verbose Enable verbosity.
 */
PEER_EXPORT void peer_test(bool verbose);

/**
 * @brief Get the zyre_t class instance providing backend connectivity
 * to the local instance of the peer class.
 *
 * @param self Local instance of peer.
 * @return zyre_t * Class instance providing backend connectivity.
 */
PEER_EXPORT zyre_t *peer_get_backend(peer_t *_Nonnull self);

/**
 * @brief Errors generated by the peer library.
 *
 */
enum PEER_ERRORS
{
    PEER_SUCCESS = 0,                               /*!< Peer operation was successful */
    PEER_EXISTS = 1,                                /*!< Peer already exists */
    PEER_NAME_LENGTH_INVALID = 2,                   /*!< Peer name longer than maximum allowed length */
    PEER_NAME_INVALID_CHARS = 3,                    /*!< Peer name contains invalid characters */
    PEER_GROUP_LENGTH_INVALID = 4,                  /*!< Peer group longer than maximum allowed length */
    PEER_GROUP_INVALID_CHARS = 5,                   /*!< Peer group contains invalid characters */
    PEER_NODE_CREATE_FAILED = 6,                    /*!< Peer zyre node creation failed */
    PEER_GROUP_HASH_FAILED = 7,                     /*!< Peer group name could not be hashed */
    PEER_PORT_RANGE_INVALID = 8,                    /*!< Peer port range invalid */
    PEER_INTERVAL_TOO_LARGE = 9,                    /*!< Peer ping interval too large */
    PEER_STRDUP_FAILED = 10,                        /*!< Peernet string duplication failed */
    PEER_ZMSG_NEW_FAILED = 11,                      /*!< Peer could not create new instance of zmsg */
    PEER_ZMSG_STR_INSERT_FAILED = 12,               /*!< Peer could not insert string into zmsg */
    PEER_ZMSG_MEM_INSERT_FAILED = 13,               /*!< Peer could not insert memory into zmsg */
    PEER_NAME_IS_NULL = 14,                         /*!< Peer name is NULL */
    PEER_MESSAGETYPE_IS_NULL = 15,                  /*!< Peer message type is NULL */
    PEER_MESSAGETYPE_LENGTH_INVALID = 16,           /*!< Peer message type length is invalid */
    PEER_MESSAGETYPE_INVALID_CHARS = 17,            /*!< Peer message type string contains invalid characters */
    PEER_MESSAGE_PAYLOAD_NULL = 18,                 /*!< Peer message payload is NULL */
    PEER_MESSAGE_PAYLOAD_LENGTH_ZERO = 19,          /*!< Peer message payload length is zero */
    PEER_DESTINATION_PEER_NOT_FOUND = 20,           /*!< Peernet destination peer not found */
    PEER_FORMAT_STR_IS_NULL = 21,                   /*!< Peernet message format string is NULL */
    PEER_NODE_START_FAILED = 22,                    /*!< Peer nodes start failed */
    PEER_NODE_GROUP_JOIN_FAILED = 23,               /*!< Peer could not join group */
    PEER_COULD_NOT_SIGNAL_PIPE = 24,                /*!< Peer could not signal to pipe */
    PEER_COULD_NOT_CREATE_ZPOLLER = 25,             /*!< Peer could not create zpoller instance */
    PEER_SELF_INSERTION_FAILED = 26,                /*!< Peer could not store information about itself */
    PEER_CALLBACK_DRIVER_FAILED = 27,               /*!< Peer message callback driver failed */
    PEER_MESSAGE_TYPE_REGISTRATION_FAILED = 28,     /*!< Peer message type registration failed */
    PEER_CALLBACK_INSERTION_FAILED = 29,            /*!< Peer callback insertion failed */
    PEER_CALLBACK_LOCALARG_INSERTION_FAILED = 30,   /*!< Peer callback local arguments insertion failed */
    PEER_CALLBACK_LIST_CREATION_FAILED = 31,        /*!< Peer callback list creation failed */
    PEER_CALLBACK_ARG_LIST_CREATION_FAILED = 32,    /*!< Peer callback arguments list creation failed */
    PEER_CALLBACK_TABLE_INSERTION_FAILED = 33,      /*!< Peer callback table insertion failed */
    PEER_CALLBACK_ARGS_TABLE_INSERTION_FAILED = 34, /*!< Peer callback arguments table insertion failed */
    PEER_GROUP_IS_NULL = 35,                        /*!< Peer group is NULL */
    PEER_ZYRE_WHISPER_FAILED = 36,                  /*!< Peer whisper message failed */
    PEER_ZYRE_WHISPERS_FAILED = 37,                 /*!< Peer whisper string failed */
    PEER_ZYRE_SHOUT_FAILED = 38,                    /*!< Peer shout message failed */
    PEER_ZYRE_SHOUTS_FAILED = 39,                   /*!< Peer shout string failed */
    PEER_ZYRE_PEER_ADDRESS_NOT_FOUND = 40,          /*!< Peer address not found */
    PEER_ZYRE_PEER_HEADER_VALUE_FAILED = 41,        /*!< Peer header value could not be retrieved */
    PEER_MESSAGE_TYPE_NOT_REGISTERED = 42,          /*!< Peer message type not registered */
    PEER_CALLBACK_DOES_NOT_EXIST = 43,              /*!< Peer callback does not exist */
    PEER_STRCONCAT_FAILED = 44,                     /*!< Peer string concatenation failed */
    PEER_RECEIVER_FAILED = 45,                      /*!< Peer receiver initialization failed */
    PEER_BOOTED = 46,                               /*!< Peer booted because of inactivity */
    PEER_AUTH_REQUEST_TIMEDOOUT = 47,               /*!< Peer authentication request timed out */
    PEER_AUTH_SEND_FAILED = 48,                     /*!< Peer authentication data could not be sent */
    PEER_AUTH_DATA_EMPTY = 49,                      /*!< Peer authentication data empty */
    PEER_AUTH_DATA_FRAME_INVALID = 50,              /*!< Peer authentication data frame invalid */
    PEER_AUTH_DATA_SIZE_INVALID = 51,               /*!< Peer authentication data size invalid */
    PEER_AUTH_KEY_INVALID = 52,                     /*!< Peer authentication key invalid */
    PEER_AUTH_FAILED = 53,                          /*!< Peer authentication failed */
    PEER_BLACKLISTED = 54,                          /*!< Blacklisted peer attempted connection */
    PEER_PASSWORD_IS_NULL = 55,                     /*!< Peer password is NULL. */
    PEER_PASSWORD_LENGTH_INVALID = 56,              /*!< Peer password length is invalid. */
    PEER_PASSWORD_INVALID_CHARS = 57,               /*!< Peer password contains invalid characers. */
    PEER_ZPOLLER_TIMED_OUT = 58,                    /*!< Peer zpoller timed out */
    PEER_MAX_ERROR
};
#ifdef __cplusplus
}
#endif

#endif