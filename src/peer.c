/**
 * @file peernet.c
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief Implementations file for PeerNet API.
 * @version See library version
 * @date 2022-09-18
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "peer.h"
#include "peer_private.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "peer_md5sum.h"

#define eprintlf(fmt, ...)                                                      \
    {                                                                           \
        fprintf(stderr, "%s,%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__); \
        fflush(stderr);                                                         \
    }

#define CALLBACK_CMD_STR "CALLBACK"
#define CALLBACK_CONNECT_STR "CONNECT"
#define CALLBACK_CONNECT_ALL_STR "CONNECT_ALL"
#define CALLBACK_DISCONNECT_STR "LEAVE"
#define CALLBACK_DISCONNECT_ALL_STR "LEAVE_ALL"
#define CALLBACK_MESSAGE_STR "MESSAGE"
#define INTERNAL_MESSAGE_STR "INTERNAL_MSG"
#define EXTERNAL_MESSAGE_STR "EXTERNAL_MSG"
#define CALLBACK_EVASIVE_STR "EVASIVE"
#define CALLBACK_SILENT_STR "SILENT"
#define PEER_EXIT_COMMAND "PEER_EXIT_REQUESTED"

static const char *peernet_error_str[PEER_MAX_ERROR] = {
    "Success",                                              // 0
    "Peer already exists",                                  // 1
    "Peer name longer than maximum allowed length",         // 2
    "Peer name contains invalid characters",                // 3
    "Peer group longer than maximum allowed length",        // 4
    "Peer group contains invalid characters",               // 5
    "Peer zyre node creation failed",                       // 6
    "Peer group name could not be hashed",                  // 7
    "Peer port range invalid",                              // 8
    "Peer ping interval too large",                         // 9
    "Peernet string duplication failed",                    // 10
    "Peer could not create new instance of zmsg",           // 11
    "Peer could not insert string into zmsg",               // 12
    "Peer could not insert memory into zmsg",               // 13
    "Peer name is NULL",                                    // 14
    "Peer message type is NULL",                            // 15
    "Peer message type length is invalid",                  // 16
    "Peer message type string contains invalid characters", // 17
    "Peer message payload is NULL",                         // 18
    "Peer message payload length is zero",                  // 19
    "Peernet destination peer not found",                   // 20
    "Peernet message format string is NULL",                // 21
    "Peer nodes start failed",                              // 22
    "Peer could not join group",                            // 23
    "Peer could not signal to pipe",                        // 24
    "Peer could not create zpoller instance",               // 25
    "Peer could not store information about itself",        // 26
    "Peer message callback driver failed",                  // 27
    "Peer message type registration failed",                // 28
    "Peer callback insertion failed",                       // 29
    "Peer callback local arguments insertion failed",       // 30
    "Peer callback list creation failed",                   // 31
    "Peer callback arguments list creation failed",         // 32
    "Peer callback table insertion failed",                 // 33
    "Peer callback arguments table insertion failed",       // 34
    "Peer group is NULL",                                   // 35
    "Peer whisper message failed",                          // 36
    "Peer whisper string failed",                           // 37
    "Peer shout message failed",                            // 38
    "Peer shout string failed",                             // 39
    "Peer address not found",                               // 40
    "Peer header value could not be retrieved",             // 41
    "Peer message type not registered",                     // 42
    "Peer callback does not exist",                         // 43
    "Peer string concatenation failed",                     // 44
    "Peer receiver initialization failed",                  // 45
    "Peer booted because of inactivity",                    // 46
    "Peer authentication request timed out",                // 47
    "Peer authentication data could not be sent",           // 48
    "Peer authentication data empty",                       // 49
    "Peer authentication data frame invalid",               // 50
    "Peer authentication data size invalid",                // 51
    "Peer authentication key invalid",                      // 52
    "Peer authentication failed",                           // 53
    "Peer zpoller timed out"                                // 54
};

#ifdef __WINDOWS__
__declspec(thread) int peer_errno = PEER_SUCCESS;
#else
__thread int peer_errno = PEER_SUCCESS;
#endif

struct _peer_t
{
    zyre_t *node;
    zactor_t *receiver;
    zactor_t *callback_driver;
    char *name;
    char *group;
    char *group_hash;
    bool started;
    bool exited;
    bool verbose;
    bool evict_on_silent;                 // evict connected peers if they are silent, false by default
    int retry_count;                      // max number of retries per peer
    int64_t auth_wait_time;               // max time to wait before authentication is hopeless (ms)
    int evasive_timeout;                  // evasive timeout in ms
    uint8_t *auth_password;               // authentication password MD5 hash
    peer_callback_t all_on_connect_cb;    // common CB for new connections
    void *all_on_connect_cb_args;         // common CB args for new connections
    peer_callback_t all_on_disconnect_cb; // common CB for disconnect
    void *all_on_disconnect_cb_args;      // common CB args for disconnect
    zlist_t *blacklist_uuids;             // blacklist of UUIDs
    zhash_t *provisional_peers;           // provisionally accepted peers
    zhash_t *available_peers;             // zhash of peers, keyed by name
    zhash_t *available_uuids;             // zhash of peers, keyed by uuid
    zhash_t *peer_retries;                // zhash of retries, keyed by name
    zhash_t *on_connect_cbs;              // zhash of callback fcns, keyed by name
    zhash_t *on_connect_cb_args;          // zhash of callback fcn args, keyed by name
    zhash_t *on_exit_cbs;                 // zhash of callback fcns, keyed by name
    zhash_t *on_exit_cb_args;             // zhash of callback fcn args, keyed by name
    zhash_t *on_silent_cbs;               // zhash of callback fcns, keyed by name
    zhash_t *on_silent_cb_args;           // zhash of callback fcn args, keyed by name
    zhash_t *on_evasive_cbs;              // zhash of callback fcns, keyed by name
    zhash_t *on_evasive_cb_args;          // zhash of callback fcn args, keyed by name
    zhash_t *on_message_cbs;              // callback functions keyed by message type
    zhash_t *on_message_cb_args;          // callback function args keyed by message type

    int peer_errno;                          // internal errno for python
    peer_py_callback_t py_all_on_connect_cb; // python callbacks
    peer_py_callback_t py_all_on_exit_cb;
    zhash_t *py_on_connect_cbs;
    zhash_t *py_on_exit_cbs;
    zhash_t *py_on_evasive_cbs;
    zhash_t *py_on_silent_cbs;
    zhash_t *py_on_message_cbs;
};

// ------------------ HELPER FUNCTIONS -------------------- //

#define destroy_ptr(ptr) \
    {                    \
        if (ptr)         \
        {                \
            free(ptr);   \
            ptr = NULL;  \
        }                \
    }

#define destroy_ptr_p(ptr_p) \
    {                        \
        if (*ptr_p)          \
        {                    \
            free(*ptr_p);    \
            *ptr_p = NULL;   \
        }                    \
    }

/**
 * @brief Check if key exists in the hash map.
 *
 * @param hash Hash instance (zhash_t)
 * @param key String key
 * @return int 0 for false, 1 for true
 */
int zhash_exists(zhash_t *hash, const char *key)
{
    zlist_t *key_list = zhash_keys(hash);
    assert(key_list);
    int rc = 0;
    char *in_key;
    for (in_key = zlist_first(key_list); in_key; in_key = zlist_next(key_list))
    {
        if (streq(in_key, key))
        {
            rc = 1;
            break;
        }
    }
    zlist_destroy(&key_list);
    return rc;
}

const char *peer_strerror(int error_code)
{
    static const char *invalid_msg = "Invalid error code.";
    if (error_code > 0)
    {
        return invalid_msg;
    }
    error_code = -error_code;
    if (error_code > PEER_MAX_ERROR)
    {
        return invalid_msg;
    }
    return peernet_error_str[error_code];
}

static inline bool valid_name_str(const char *name)
{
    bool name_valid = true;
    char *s = (char *)name;
    while (*s & name_valid)
    {
        name_valid &= (isalnum(*s) || ((*s) == '_'));
        s++;
    }
    return name_valid;
}

static inline void str_to_upper(char *name)
{
    char *s = name;
    while (*s)
    {
        *s = toupper((unsigned char)*s);
        s++;
    }
}

static const char *find_name(peer_t *self, const char *name)
{
    assert(self);
    assert(self->node);
    assert(name);
    assert(self->available_peers);

    char *_name = strdup(name);
    assert(_name);

    str_to_upper(_name);

    const char *uuid = zhash_lookup(self->available_peers, _name);
    destroy_ptr(_name);

    return uuid;
}

int peer_py_validate_name(const char *name)
{
    if (!name)
    {
        return -PEER_NAME_IS_NULL;
    }
    if (strlen(name) > PEER_NAME_MAXLEN)
    {
        return -PEER_NAME_LENGTH_INVALID;
    }
    if (strlen(name) < PEER_NAME_MINLEN)
    {
        return -PEER_NAME_LENGTH_INVALID;
    }
    if (!valid_name_str(name))
    {
        return -PEER_NAME_INVALID_CHARS;
    }
    return 0;
}

static inline int validate_name(const char *name)
{
    if (!name)
    {
        peer_errno = -PEER_NAME_IS_NULL;
        return 0;
    }
    if (strlen(name) > PEER_NAME_MAXLEN)
    {
        peer_errno = -PEER_NAME_LENGTH_INVALID;
        return 0;
    }
    if (strlen(name) < PEER_NAME_MINLEN)
    {
        peer_errno = -PEER_NAME_LENGTH_INVALID;
        return 0;
    }
    if (!valid_name_str(name))
    {
        peer_errno = -PEER_NAME_INVALID_CHARS;
        return 0;
    }
    peer_errno = PEER_SUCCESS;
    return 1;
}

static inline int _validate_name(peer_t *self, const char *name)
{
    if (!name)
    {
        peer_errno = -PEER_NAME_IS_NULL;
        self->peer_errno = -PEER_NAME_IS_NULL;
        return 0;
    }
    if (strlen(name) > PEER_NAME_MAXLEN)
    {
        self->peer_errno = -PEER_NAME_LENGTH_INVALID;
        peer_errno = -PEER_NAME_LENGTH_INVALID;
        return 0;
    }
    if (strlen(name) < PEER_NAME_MINLEN)
    {
        self->peer_errno = -PEER_NAME_LENGTH_INVALID;
        peer_errno = -PEER_NAME_LENGTH_INVALID;
        return 0;
    }
    if (!valid_name_str(name))
    {
        self->peer_errno = -PEER_NAME_INVALID_CHARS;
        peer_errno = -PEER_NAME_INVALID_CHARS;
        return 0;
    }
    self->peer_errno = PEER_SUCCESS;
    peer_errno = PEER_SUCCESS;
    return 1;
}

static inline int validate_group(const char *group)
{
    if (!group)
    {
        peer_errno = -PEER_GROUP_IS_NULL;
        return 0;
    }
    int name_len = strlen(group);
    if (name_len > PEER_GROUP_MAXLEN)
    {
        peer_errno = -PEER_GROUP_LENGTH_INVALID;
        return 0;
    }
    if (name_len < PEER_GROUP_MINLEN)
    {
        peer_errno = -PEER_GROUP_LENGTH_INVALID;
        return 0;
    }
    bool name_valid = valid_name_str(group);
    if (!name_valid)
    {
        peer_errno = -PEER_GROUP_INVALID_CHARS;
        return 0;
    }
    peer_errno = PEER_SUCCESS;
    return 1;
}

int peer_py_validate_group(const char *group)
{
    if (!group)
    {
        return -PEER_GROUP_IS_NULL;
    }
    int name_len = strlen(group);
    if (name_len > PEER_GROUP_MAXLEN)
    {
        return -PEER_GROUP_LENGTH_INVALID;
    }
    if (name_len < PEER_GROUP_MINLEN)
    {
        return -PEER_GROUP_LENGTH_INVALID;
    }
    bool name_valid = valid_name_str(group);
    if (!name_valid)
    {
        return -PEER_GROUP_INVALID_CHARS;
    }
    return PEER_SUCCESS;
}

int peer_py_validate_message_type(const char *message_type)
{
    if (!message_type)
    {
        return -PEER_MESSAGETYPE_IS_NULL;
    }
    if (strlen(message_type) > PEER_MESSAGETYPE_MAXLEN)
    {
        return -PEER_MESSAGETYPE_LENGTH_INVALID;
    }
    if (strlen(message_type) < PEER_MESSAGETYPE_MINLEN)
    {
        return -PEER_MESSAGETYPE_LENGTH_INVALID;
    }
    if (!valid_name_str(message_type))
    {
        return -PEER_MESSAGETYPE_INVALID_CHARS;
    }
    return 0;
}

static inline int validate_message_type(const char *message_type)
{
    if (!message_type)
    {
        peer_errno = -PEER_MESSAGETYPE_IS_NULL;
        return 0;
    }
    if (strlen(message_type) > PEER_MESSAGETYPE_MAXLEN)
    {
        peer_errno = -PEER_MESSAGETYPE_LENGTH_INVALID;
        return 0;
    }
    if (strlen(message_type) < PEER_MESSAGETYPE_MINLEN)
    {
        peer_errno = -PEER_MESSAGETYPE_LENGTH_INVALID;
        return 0;
    }
    if (!valid_name_str(message_type))
    {
        peer_errno = -PEER_MESSAGETYPE_INVALID_CHARS;
        return 0;
    }
    peer_errno = PEER_SUCCESS;
    return 1;
}

static inline int _validate_message_type(peer_t *self, const char *message_type)
{
    if (!message_type)
    {
        peer_errno = -PEER_MESSAGETYPE_IS_NULL;
        self->peer_errno = -PEER_MESSAGETYPE_IS_NULL;
        return 0;
    }
    if (strlen(message_type) > PEER_MESSAGETYPE_MAXLEN)
    {
        peer_errno = -PEER_MESSAGETYPE_LENGTH_INVALID;
        self->peer_errno = -PEER_MESSAGETYPE_LENGTH_INVALID;
        return 0;
    }
    if (strlen(message_type) < PEER_MESSAGETYPE_MINLEN)
    {
        peer_errno = -PEER_MESSAGETYPE_LENGTH_INVALID;
        self->peer_errno = -PEER_MESSAGETYPE_LENGTH_INVALID;
        return 0;
    }
    if (!valid_name_str(message_type))
    {
        peer_errno = -PEER_MESSAGETYPE_INVALID_CHARS;
        self->peer_errno = -PEER_MESSAGETYPE_INVALID_CHARS;
        return 0;
    }
    peer_errno = PEER_SUCCESS;
    self->peer_errno = PEER_SUCCESS;
    return 1;
}

static inline int validate_password(const char *password)
{
    if (!password)
    {
        peer_errno = -PEER_PASSWORD_IS_NULL;
        return 0;
    }
    if (strlen(password) > PEER_PASSWORD_MAXLEN)
    {
        peer_errno = -PEER_PASSWORD_LENGTH_INVALID;
        return 0;
    }
    if (strlen(password) < PEER_PASSWORD_MINLEN)
    {
        peer_errno = -PEER_PASSWORD_LENGTH_INVALID;
        return 0;
    }
    if (!valid_name_str(password))
    {
        peer_errno = -PEER_PASSWORD_INVALID_CHARS;
        return 0;
    }
    peer_errno = PEER_SUCCESS;
    return 1;
}

static inline void peer_invoke_callback(peer_t *self, const char *name, const char *callback_type)
{
    zmsg_t *callback_msg = zmsg_new();
    if (!callback_msg)
    {
        zsys_error("Could not allocate memory to request callback execution.");
    }
    else
    {
        zmsg_addstr(callback_msg, CALLBACK_CMD_STR);
        zmsg_addstr(callback_msg, callback_type);
        zmsg_addstr(callback_msg, "FIXED_CB"); // message_type
        zmsg_addstr(callback_msg, name);       // peer name
        if (self->verbose)
        {
            zsys_info("To Callback: %s %s %s %s", CALLBACK_CMD_STR, callback_type, "FIXED_CB", name);
        }
        zmsg_send(&callback_msg, self->callback_driver);
    }
}

static inline void peer_invoke_message_callback(peer_t *self, const char *name, const char *message_type, zframe_t *data)
{
    zmsg_t *callback_msg = zmsg_new();
    if (!callback_msg)
    {
        zsys_error("Could not allocate memory to request callback execution.");
    }
    else
    {
        zmsg_addstr(callback_msg, CALLBACK_CMD_STR);
        zmsg_addstr(callback_msg, CALLBACK_MESSAGE_STR);
        zmsg_addstr(callback_msg, message_type); // message_type
        zmsg_addstr(callback_msg, name);         // peer name
        zmsg_append(callback_msg, &data);
        if (self->verbose)
        {
            zsys_info("To Callback: %s %s %s %s", CALLBACK_CMD_STR, CALLBACK_MESSAGE_STR, message_type, name);
        }
        zmsg_send(&callback_msg, self->callback_driver);
    }
}

/**
 * @brief Compare two MD5 hash values
 *
 * @param p1 Pointer to uint8_t[16] hash
 * @param p2 Pointer to uint8_t[16] hash
 * @return bool
 */
static inline bool auth_hash_compare(void *p1, void *p2)
{
    bool out = true;
    uint8_t *s1 = (uint8_t *)p1;
    uint8_t *s2 = (uint8_t *)p2;
    for (int i = 0; (i < 16) && out; i++)
    {
        if (s1[i] != s2[i])
        {
            out = false;
        }
    }
    return out;
}

// ---------------- END HELPER FUNCTIONS -------------------- //

static void callback_actor(zsock_t *pipe, void *arg)
{
    assert(pipe);
    assert(arg);
    peer_t *self = (peer_t *)arg;
    int local_errno = PEER_SUCCESS;
    bool terminated = false;
    int executed = 0;
    zpoller_t *poller = zpoller_new(pipe, NULL);
    if (!poller)
    {
        local_errno = -PEER_COULD_NOT_CREATE_ZPOLLER;
        goto errored;
    }
    assert(!zsock_signal(pipe, PEER_SUCCESS)); // zactor_new returns in caller
    assert(!zsock_signal(pipe, PEER_SUCCESS)); // caller verifies init
    while (!terminated)
    {
        void *which = zpoller_wait(poller, -1);
        if (which == pipe) // the only option
        {
            zmsg_t *msg = zmsg_recv(which);
            char *command = zmsg_popstr(msg);
            if (streq(command, "$TERM"))
            {
                terminated = true;
            }
            else if (streq(command, CALLBACK_CMD_STR))
            {
                bool py_cb_exists = true;
                bool c_cb_exists = true;
                peer_py_callback_t pcb = NULL;
                peer_callback_t cb = NULL;
                void *local_args = NULL;
                void *remote_args = NULL;
                size_t remote_args_len = 0;
                char hash[PEER_MESSAGETYPE_MAXLEN + PEER_NAME_MAXLEN + 1] = {
                    0x0,
                };
                int len = 0;
                // 1. Retrieve contents
                char *callback_type = zmsg_popstr(msg);
                char *message_type = zmsg_popstr(msg);
                char *remote_name = zmsg_popstr(msg);
                zframe_t *frame = NULL;
                // 2. Validate contents
                if (!callback_type)
                {
                    zsys_error("Callback Actor: Callback type is NULL.");
                    goto loop_reset;
                }
                if (!message_type)
                {
                    zsys_error("Callback Actor: Message type is NULL.");
                    goto loop_reset;
                }
                if (!remote_name)
                {
                    zsys_error("Callback Actor: Peer name is NULL.");
                    goto loop_reset;
                }
                len = snprintf(hash, sizeof(hash), "%s.%s", message_type, remote_name);
                if (len != strlen(message_type) + strlen(remote_name) + 1)
                {
                    zsys_error("Callback Actor: Frame hash length mismatch [%d != %d + %d + 1]", len, strlen(message_type), strlen(remote_name));
                    goto loop_reset;
                }
                // 3. Retrieve callback functions
                if (streq(callback_type, CALLBACK_CONNECT_STR)) // for on_connect calls
                {
                    if (!zhash_exists(self->py_on_connect_cbs, remote_name))
                    {
                        py_cb_exists = false;
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Python connect callback for %s not registered.", remote_name);
                        }
                    }
                    if (!zhash_exists(self->on_connect_cbs, remote_name))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Connect callback for %s not registered.", remote_name);
                        }
                        c_cb_exists = false;
                    }
                    if (!zhash_exists(self->on_connect_cb_args, remote_name))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Callback local argument from %s not registered.", remote_name);
                        }
                        zhash_delete(self->on_connect_cbs, remote_name);
                        c_cb_exists = false;
                    }
                    if (c_cb_exists)
                    {
                        cb = zhash_lookup(self->on_connect_cbs, remote_name);
                        local_args = zhash_lookup(self->on_connect_cb_args, remote_name);
                    }
                    if (py_cb_exists)
                    {
                        pcb = zhash_lookup(self->py_on_connect_cbs, remote_name);
                    }
                    if ((!c_cb_exists) && (!py_cb_exists))
                    {
                        goto loop_reset;
                    }
                }
                else if (streq(callback_type, CALLBACK_CONNECT_ALL_STR)) // for on_connect calls
                {
                    pcb = self->py_all_on_connect_cb;
                    cb = self->all_on_connect_cb;
                    local_args = self->all_on_connect_cb_args;
                    if (self->verbose)
                    {
                        zsys_info("Callback Actor: Callback all connect: %p, %p, %p", pcb, cb, local_args);
                    }
                }
                else if (streq(callback_type, CALLBACK_DISCONNECT_STR)) // for on_disconnect calls
                {
                    if (!zhash_exists(self->py_on_exit_cbs, remote_name))
                    {
                        py_cb_exists = false;
                    }
                    if (!zhash_exists(self->on_exit_cbs, remote_name))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Exit callback for %s not registered.", remote_name);
                        }
                        c_cb_exists = false;
                    }
                    if (!zhash_exists(self->on_exit_cb_args, remote_name))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Callback local argument from %s not registered.", remote_name);
                        }
                        zhash_delete(self->on_exit_cbs, remote_name);
                        c_cb_exists = false;
                    }
                    if (c_cb_exists)
                    {
                        cb = zhash_lookup(self->on_exit_cbs, remote_name);
                        local_args = zhash_lookup(self->on_exit_cb_args, remote_name);
                    }
                    if (py_cb_exists)
                    {
                        pcb = zhash_lookup(self->py_on_exit_cbs, remote_name);
                    }
                    if ((!c_cb_exists) && (!py_cb_exists))
                    {
                        goto loop_reset;
                    }
                }
                else if (streq(callback_type, CALLBACK_DISCONNECT_ALL_STR)) // for on_connect calls
                {
                    pcb = self->py_all_on_exit_cb;
                    cb = self->all_on_disconnect_cb;
                    local_args = self->all_on_disconnect_cb_args;
                }
                else if (streq(callback_type, CALLBACK_EVASIVE_STR)) // for on_disconnect calls
                {
                    if (!zhash_exists(self->py_on_evasive_cbs, remote_name))
                    {
                        py_cb_exists = false;
                    }
                    if (!zhash_exists(self->on_evasive_cbs, remote_name))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Evasive callback for %s not registered.", remote_name);
                        }
                        c_cb_exists = false;
                    }
                    if (!zhash_exists(self->on_evasive_cb_args, remote_name))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Callback local argument from %s not registered.", remote_name);
                        }
                        zhash_delete(self->on_evasive_cbs, remote_name);
                        c_cb_exists = false;
                    }
                    if (c_cb_exists)
                    {
                        cb = zhash_lookup(self->on_evasive_cbs, remote_name);
                        local_args = zhash_lookup(self->on_evasive_cb_args, remote_name);
                    }
                    if (py_cb_exists)
                    {
                        pcb = zhash_lookup(self->py_on_evasive_cbs, remote_name);
                    }
                    if ((!c_cb_exists) && (!py_cb_exists))
                    {
                        goto loop_reset;
                    }
                }
                else if (streq(callback_type, CALLBACK_SILENT_STR)) // for on_disconnect calls
                {
                    if (!zhash_exists(self->py_on_silent_cbs, remote_name))
                    {
                        py_cb_exists = false;
                    }
                    if (!zhash_exists(self->on_silent_cbs, remote_name))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Silent callback for %s not registered.", remote_name);
                        }
                        c_cb_exists = false;
                    }
                    if (!zhash_exists(self->on_silent_cb_args, remote_name))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Callback local argument from %s not registered.", remote_name);
                        }
                        zhash_delete(self->on_silent_cbs, remote_name);
                        c_cb_exists = false;
                    }
                    if (c_cb_exists)
                    {
                        cb = zhash_lookup(self->on_silent_cbs, remote_name);
                        local_args = zhash_lookup(self->on_silent_cb_args, remote_name);
                    }
                    if (py_cb_exists)
                    {
                        pcb = zhash_lookup(self->py_on_silent_cbs, remote_name);
                    }
                    if ((!c_cb_exists) && (!py_cb_exists))
                    {
                        goto loop_reset;
                    }
                }
                else if (streq(callback_type, CALLBACK_MESSAGE_STR)) // for on_message calls
                {
                    frame = zmsg_pop(msg);
                    if (!frame)
                    {
                        zsys_error("Callback Actor: Callback for %s from %s does not contain any remote data.", message_type, remote_name);
                        goto loop_reset;
                    }
                    if (!zframe_is(frame))
                    {
                        zsys_error("Callback Actor: Callback for %s from %s does not contain a valid remote data frame.", message_type, remote_name);
                        goto loop_reset;
                    }
                    remote_args = zframe_data(frame);
                    remote_args_len = zframe_size(frame);
                    if (!zhash_exists(self->py_on_message_cbs, hash))
                    {
                        py_cb_exists = false;
                    }
                    if (!zhash_exists(self->on_message_cbs, hash))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Callback for %s from %s not registered.", message_type, remote_name);
                        }
                        c_cb_exists = false;
                    }
                    if (c_cb_exists && !zhash_exists(self->on_message_cb_args, hash))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Callback local argument for %s from %s not registered.", message_type, remote_name);
                        }
                        zhash_delete(self->on_message_cbs, hash);
                        c_cb_exists = false;
                    }
                    if (c_cb_exists)
                    {
                        cb = zhash_lookup(self->on_message_cbs, hash);
                        local_args = zhash_lookup(self->on_message_cb_args, hash);
                    }
                    if (py_cb_exists)
                    {
                        pcb = zhash_lookup(self->py_on_message_cbs, hash);
                        if (self->verbose)
                        {
                            zsys_info("%s> Python callback for %s from %s: %p", message_type, remote_name, pcb);
                        }
                    }
                    if ((!c_cb_exists) && (!py_cb_exists))
                    {
                        goto loop_reset;
                    }
                }
                else
                {
                    if (strlen(callback_type) > 50)
                    {
                        callback_type[51] = '\0'; // limit length
                    }
                    zsys_error("Callback Actor: Unknown callback type %s.", (callback_type));
                    goto loop_reset;
                }
                // 4. Execute the callback function
                // zsock_send(pipe, "i", executed++);
                if (pcb)
                {
                    if (self->verbose)
                    {
                        zsys_info("Executing python callback function at %p: inputs %p(%d)[%s] %p(%d)[%s] %p(%d)", pcb, message_type, strlen(message_type) + 1, message_type, remote_name, strlen(remote_name) + 1, remote_name, remote_args, (int)remote_args_len);
                    }
                    pcb(self, message_type, (size_t)(strlen(message_type) + 1), remote_name, (size_t)(strlen(remote_name) + 1), remote_args, (size_t)remote_args_len);
                }
                if (cb)
                {
                    if (self->verbose)
                    {
                        zsys_info("Executing callback function at %p.", cb);
                    }
                    cb(self, message_type, remote_name, local_args, remote_args, remote_args_len);
                }
                else
                {
                    zsys_info("Callback function is NULL for %s from %s.", message_type, remote_name);
                }
                // zsock_send(pipe, "i", executed);
                if (self->verbose)
                {
                    zsys_info("Executed callback function at %p", cb);
                }
                // 5. Free stuff
            loop_reset:
                destroy_ptr(callback_type);
                destroy_ptr(message_type);
                destroy_ptr(remote_name);
                if (frame)
                    zframe_destroy(&frame);
            }
            free(command);
            zmsg_destroy(&msg);
        }
    }
    zpoller_destroy(&poller);
    zsock_signal(pipe, PEER_SUCCESS);
    return;
errored:
    assert(!zsock_signal(pipe, PEER_SUCCESS)); // return zactor_new
    assert(!zsock_signal(pipe, -local_errno)); // return error message to caller
    return;
}

static void receiver_actor(zsock_t *pipe, void *_args) // Forward declaration.
{
    struct _peer_t *self = (peer_t *)_args;
    int local_errno = PEER_SUCCESS;
    zyre_t *node = self->node;
    int rc = 0;
    bool exited_on_request = false;
    bool attempted_auth = false;
    self->callback_driver = zactor_new(callback_actor, self);
    if (!self->callback_driver)
    {
        local_errno = -PEER_CALLBACK_DRIVER_FAILED;
        goto errored;
    }
    rc = zsock_wait(self->callback_driver);
    if (rc)
    {
        local_errno = -PEER_CALLBACK_DRIVER_FAILED;
        goto errored_destroy;
    }
    rc = zyre_start(node);
    if (rc)
    {
        local_errno = -PEER_NODE_START_FAILED;
        goto errored_destroy;
    }
    rc = zyre_join(node, self->group_hash);
    if (rc)
    {
        local_errno = -PEER_NODE_GROUP_JOIN_FAILED;
        goto errored_destroy;
    }
    zpoller_t *poller = zpoller_new(pipe, zyre_socket(node), NULL);
    if (!poller)
    {
        local_errno = -PEER_COULD_NOT_CREATE_ZPOLLER;
        goto errored_destroy;
    }
    assert(!zsock_signal(pipe, PEER_SUCCESS)); // clear zactor_new
    assert(!zsock_signal(pipe, PEER_SUCCESS)); // let caller know of status
    bool terminated = false;
    int timeout = self->auth_wait_time - 1000;
    int64_t tstamp = 0;
    while (!terminated)
    {
        if ((timeout != -1) && (!attempted_auth) && (self->started))
        {
            timeout = -1;
        }
        void *which = zpoller_wait(poller, timeout);

        if ((which == NULL) && (zpoller_expired(poller))) // we don't care about SIGINT, peer creator does.
        {
            zsys_info("%s> Poller timed out", self->name);
            // check if authentication time period has expired
            if (attempted_auth)
            {
                int64_t tnow = zclock_mono();
                if (tnow < tstamp)
                {
                    // what the fuck? exit now
                    assert(false);
                }
                else if (tnow - tstamp > self->auth_wait_time)
                {
                    zsock_send(pipe, "i", -PEER_AUTH_REQUEST_TIMEDOOUT);
                    break;
                }
                else
                {
                    continue;
                }
            }
            else if (!self->started)
            {
                zsys_info("%s> Heard nothing, probably only one here. Can take ownership of group %s.", self->name, self->group);
                zsock_send(pipe, "i", PEER_SUCCESS);
                timeout = -1;
            }
        }

        else if (which == pipe) // do not really expect too many pipe messages
        {
            zmsg_t *msg = zmsg_recv(which);
            if (!msg)
            {
                break; // interrupted
            }
            char *command = zmsg_popstr(msg);
            if (streq(command, "$TERM"))
            {
                // leave group
                zyre_leave(node, self->group_hash);
                terminated = true;
            }
            free(command);
            zmsg_destroy(&msg);
        }

        else if (which == zyre_socket(node))
        {
            zmsg_t *msg = zmsg_recv(which);
            char *event = zmsg_popstr(msg);
            char *uuid = zmsg_popstr(msg);
            char *name = zmsg_popstr(msg);
            char *group = zmsg_popstr(msg);
            char *internal_msg = zmsg_popstr(msg);
            char *message_type = zmsg_popstr(msg);

            if (group == NULL)
            {
                group = strdup("");
            }

            if (streq(event, "WHISPER") && streq(internal_msg, INTERNAL_MESSAGE_STR) && streq(group, self->group_hash)) // check internal messages
            {
                if (streq(message_type, "NAME_CONFLICT_EVICT")) // remote
                {
                    zsock_send(pipe, "i", -PEER_EXISTS);
                    terminated = true;
                }
                else if (streq(message_type, "SEND_AUTH"))
                {
                    int rc = peer_whisper_internal(self, uuid, INTERNAL_MESSAGE_STR, "PEER_AUTH_DATA", self->auth_password, 16); // md5 hash
                    // do something with time at this point
                    if (rc)
                    {
                        zsock_send(pipe, "i", -PEER_AUTH_SEND_FAILED);
                        terminated = true;
                    }
                    else
                    {
                        attempted_auth = true;
                        tstamp = zclock_mono();
                    }
                }
                else if (streq(message_type, "PEER_AUTH_SUCCESS")) // remote
                {
                    attempted_auth = false;
                    timeout = -1;
                    zsock_send(pipe, "i", PEER_SUCCESS);
                }
                else if (streq(message_type, "PEER_AUTH_DATA") && zhash_exists(self->provisional_peers, name))
                {
                    bool accept = true;
                    int local_err = PEER_SUCCESS;
                    zframe_t *data = zmsg_pop(msg);
                    if (!data)
                    {
                        accept = false;
                        local_err = -PEER_AUTH_DATA_EMPTY;
                        zsock_send(pipe, "i", local_err);
                        if (self->verbose)
                        {
                            zsys_error("%s> No auth key from %s", self->name, name);
                        }
                    }
                    else if (!zframe_is(data))
                    {
                        accept = false;
                        local_err = -PEER_AUTH_DATA_FRAME_INVALID;
                        zsock_send(pipe, "i", local_err);
                        if (self->verbose)
                        {
                            zsys_error("%s> Invalid auth key frame from %s", self->name, name);
                        }
                    }
                    else if (zframe_size(data) != 16)
                    {
                        accept = false;
                        local_err = -PEER_AUTH_DATA_SIZE_INVALID;
                        zsock_send(pipe, "i", local_err);
                        if (self->verbose)
                        {
                            zsys_error("%s> Invalid auth key size from %s", self->name, name);
                        }
                    }
                    else if (!auth_hash_compare(self->auth_password, zframe_data(data)))
                    {
                        accept = false;
                        local_err = -PEER_AUTH_KEY_INVALID;
                        zsock_send(pipe, "i", local_err);
                        if (self->verbose)
                        {
                            zsys_error("%s> Invalid auth key from %s", self->name, name);
                        }
                    }
                    if (accept)
                    {
                        // send auth
                        int rc = peer_whisper_internal(self, uuid, INTERNAL_MESSAGE_STR, "PEER_AUTH_SUCCESS", NULL, 0); // automatically counts as name valid
                        if (rc)
                        {
                            // could not send auth, remove peer from our tentative list so that they can reconnect. But how does the remote peer know of this incident?
                            // if peer has already disconnected this would be fine
                            zhash_delete(self->provisional_peers, name);
                        }
                        else
                        {
                            // do stuff for induction
                            zhash_insert(self->available_peers, name, strdup(uuid));
                            zhash_insert(self->available_uuids, uuid, strdup(name)); // update inverse list as well
                            int *retry_count = (int *)malloc(sizeof(int));
                            assert(retry_count);
                            *retry_count = self->retry_count;
                            zhash_insert(self->peer_retries, name, retry_count);
                            if (self->verbose)
                            {
                                zsys_info("%s> Peer %s inducted.", self->name, name);
                            }
                            if (self->all_on_connect_cb || self->py_all_on_connect_cb)
                                peer_invoke_callback(self, name, CALLBACK_CONNECT_ALL_STR);
                            peer_invoke_callback(self, name, CALLBACK_CONNECT_STR);
                        }
                    }
                }
                else if (streq(message_type, "PEER_AUTH_FAILED"))
                {
                    zsock_send(pipe, "i", -PEER_AUTH_FAILED);
                    terminated = true;
                }
                else if (streq(message_type, PEER_EXIT_COMMAND))
                {
                    zsys_error("%s> Received EXIT request from %s", self->name, name);
                    exited_on_request = true;
                    zsock_send(pipe, "i", -PEER_BOOTED);
                    terminated = true;
                }
                // else if (streq(message_type, "NAME_OKAY"))
                // {
                //     zsock_send(pipe, "i", PEER_SUCCESS);
                // }
            }

            else if (streq(event, "JOIN")) // a peer has entered
            {
                bool in_our_group = streq(group, self->group_hash); // check if peer is in our group by comparing the group name sent by the peer against our group hash
                if (self->verbose)
                {
                    zsys_info("%s[%s] has joined [%s]\n", name, uuid, in_our_group == true ? self->group : group);
                }
                if (in_our_group) // in our group
                {
                    if ((!(zlist_exists(self->blacklist_uuids, uuid))) && (!zhash_insert(self->provisional_peers, name, strdup(uuid)))) // peer name not already in available peers list
                    {
                        if (self->verbose)
                        {
                            zsys_info("Peer name OK: %s, requesting authentication from %s!", name, uuid);
                        }
                        rc = peer_whisper_internal(self, uuid, INTERNAL_MESSAGE_STR, "SEND_AUTH", NULL, 0);
                        if (rc)
                        {
                            zsys_error("Peer name OK: %s, could not send message to %s, removing!", name, uuid);
                            zhash_delete(self->provisional_peers, name);
                        }
                        // if (self->all_on_connect_cb)
                        //     peer_invoke_callback(self, name, CALLBACK_CONNECT_ALL_STR);
                        // peer_invoke_callback(self, name, CALLBACK_CONNECT_STR);
                    }
                    else if (zlist_exists(self->blacklist_uuids, uuid))
                    {
                        zsock_send(pipe, "i", -PEER_BLACKLISTED);
                        if (self->verbose)
                        {
                            zsys_info("%s> Blacklisted peer %s[%s] tried to connect.", self->name, name, uuid);
                        }
                    }
                    else
                    {
                        if (self->verbose)
                        {
                            zsys_info("Peer name conflict: %s, sending name conflict message to %s!", name, uuid);
                        }
                        rc = peer_whisper_internal(self, uuid, INTERNAL_MESSAGE_STR, "NAME_CONFLICT_EVICT", NULL, 0);
                        if (rc)
                        {
                            zsys_error("Peer name conflict: %s, could not send message to %s!", name, uuid);
                        }
                    }
                }
            }

            else if (streq(event, "LEAVE"))
            {
                bool in_our_group = (strcmp(group, self->group_hash) == 0); // check if peer is in our group by comparing the group name sent by the peer against our group hash
                // if (self->verbose)
                // {
                //     zsys_info("%s[%s] has left [%s]\n", name, uuid, in_our_group == true ? self->group : group);
                // }
                if (in_our_group) // in our group
                {
                    zhash_delete(self->provisional_peers, name);
                    // check if UUID of leaving is in available uuids
                    if (zhash_lookup(self->available_uuids, uuid))
                    {
                        zhash_delete(self->available_peers, name);
                        zhash_delete(self->available_uuids, uuid);
                        zhash_delete(self->peer_retries, name);
                        if (self->verbose)
                        {
                            zsys_info("Peer name %s [%s] leaving.", name, uuid);
                        }
                        if (self->all_on_disconnect_cb || self->py_all_on_exit_cb)
                            peer_invoke_callback(self, name, CALLBACK_DISCONNECT_ALL_STR);
                        peer_invoke_callback(self, name, CALLBACK_DISCONNECT_STR);
                    }
                    else
                    {
                        if (self->verbose)
                        {
                            zsys_info("Conflicted peer %s[%s] leaving!", name, uuid);
                        }
                    }
                }
            }

            else if (streq(event, "EVASIVE")) // this is a hang
            {
                bool in_our_group = zhash_exists(self->available_uuids, uuid);
                if (self->verbose && in_our_group)
                {
                    zsys_info("%s[%s] is being evasive.", name, uuid);
                }
                if (in_our_group)
                {
                    int *retry_count = zhash_lookup(self->peer_retries, name);
                    if (retry_count)
                    {
                        int val = *retry_count;
                        if (val > 0)
                        {
                            val--;
                            *retry_count = val;
                        }
                        else if (val == 0) // request peer be booted
                        {
                            zhash_delete(self->available_peers, name);
                            zhash_delete(self->peer_retries, name);
                            zhash_delete(self->available_uuids, uuid);
                            peer_whisper_internal(self, uuid, INTERNAL_MESSAGE_STR, PEER_EXIT_COMMAND, NULL, 0);
                            zsys_error("%s> Sending EXIT request to %s, evasive retry 0.", self->name, name);
                            zsock_send(pipe, "i", -PEER_BOOTED);
                        }
                    }
                    peer_invoke_callback(self, name, CALLBACK_EVASIVE_STR);
                }
            }

            else if (streq(event, "SILENT")) // this is a crash
            {
                bool in_our_group = zhash_exists(self->available_uuids, uuid);
                if (self->verbose && in_our_group)
                {
                    zsys_info("%s[%s] is being silent.", name, uuid);
                }
                if (in_our_group && self->evict_on_silent)
                {
                    zsys_error("%s> Sending EXIT request to %s, peer silent.", self->name, name);
                    peer_whisper_internal(self, uuid, INTERNAL_MESSAGE_STR, PEER_EXIT_COMMAND, NULL, 0);
                    zhash_delete(self->available_peers, name);
                    zhash_delete(self->available_uuids, uuid);
                    zhash_delete(self->peer_retries, name);
                    peer_invoke_callback(self, name, CALLBACK_EVASIVE_STR);
                    zsock_send(pipe, "i", -PEER_BOOTED);
                }
            }

            else if ((streq(event, "WHISPER") || streq(event, "SHOUT")) && streq(internal_msg, EXTERNAL_MESSAGE_STR) && validate_message_type(message_type)) // user message
            {
                bool in_our_group = (streq(group, self->group_hash)); // check if peer is in our group by comparing the group name sent by the peer against our group hash
                if (self->verbose)
                {
                    zsys_info("%s[%s] has whispered [%s]", name, uuid, message_type);
                }
                zframe_t *data = zmsg_pop(msg);
                if (!zframe_is(data))
                {
                    if (self->verbose)
                    {
                        zsys_error("%s[%s] has no data in [%s]", name, uuid, message_type);
                    }
                }
                else
                {
                    peer_invoke_message_callback(self, name, message_type, data);
                }
            }

            destroy_ptr(event);
            destroy_ptr(uuid);
            destroy_ptr(name);
            destroy_ptr(group);
            destroy_ptr(internal_msg);
            destroy_ptr(message_type);
            zmsg_destroy(&msg);
        }
    }
    zpoller_destroy(&poller);
    zclock_sleep(100);
    zsock_send(self->callback_driver, "s", "$TERM"); // ask callback driver to terminate
    byte st = zsock_wait(self->callback_driver);
    if (st)
    {
        zsys_error("Callback driver exit error: %s (%d)", peer_strerror(-st), st);
    }
    zactor_destroy(&(self->callback_driver)); // destroy the callback driver
    if (!zsys_interrupted)                    // we probably have already left
        zyre_stop(node);
    zclock_sleep(100);
    zsock_signal(pipe, PEER_SUCCESS);
    self->exited = true;
    if (exited_on_request)
    {
        zsys_info(" ");
        zsys_info(" ");
        zsys_info("%s> Exiting on request.", self->name);
        zsys_info(" ");
        zsys_info(" ");
    }
    return;
errored_destroy:
    zactor_destroy(&self->callback_driver);
errored:
    self->exited = true;
    zsock_signal(pipe, 0);            // let zactor_new return
    zsock_signal(pipe, -local_errno); // let caller know of status
    zsys_error("In errored (receiver_actor for %s): %s", self->name, peer_strerror(local_errno));
    return;
}

// ------------------ CLASS FUNCTIONS -------------------- //

bool peer_exists(peer_t *self, const char *name)
{
    assert(self);
    assert(self->node);
    assert(name);
    if (!self->started)
        return false;
    if (!validate_name(name))
    {
        return false;
    }
    char *_name = strdup(name);
    str_to_upper(_name);
    return zhash_exists(self->available_peers, _name);
}

peer_t *peer_new(const char *name, const char *group, const char *password, bool encryption)
{
    peer_t *self = NULL;
    char *_name = NULL, *_group = NULL, _group_hash[33] = {
                                            0x0,
                                        };
    uint8_t *group_hash = NULL;
    zcert_t *cert = NULL;
    char *_passwd = NULL;
    // 1. Check name
    int rc = validate_name(name);
    if (!rc)
    {
        return NULL;
    }
    // 1a. Check password
    rc = validate_password(password);
    if (!rc)
    {
        return NULL;
    }
    // 2. Check group name
    if (group) // non NULL
    {
        if (!validate_group(group))
        {
            return NULL;
        }
        _group = strdup(group);
    }
    else // use default name
    {
        _group = strdup("UNIVERSAL");
    }
    assert(_group);
    str_to_upper(_group);
    _name = strdup(name);
    assert(_name);
    str_to_upper(_name);
    // 2a. Create the hash
    group_hash = peer_md5sum_md5String(_group);
    _passwd = strdup(password);
    assert(_passwd);
    if (!group_hash)
    {
        peer_errno = -PEER_GROUP_HASH_FAILED;
        goto cleanup_group;
    }
    for (int i = 0; i < 16; i++)
    {
        snprintf(&(_group_hash[i * 2]), 3, "%02X", group_hash[i]);
    }
    // 3. Create thing, create actor
    self = (peer_t *)malloc(sizeof(peer_t));
    assert(self);
    memset(self, 0x0, sizeof(peer_t));
    self->node = zyre_new(_name);
    if (!self->node)
    {
        peer_errno = -PEER_NODE_CREATE_FAILED;
        goto cleanup_all;
    }
    if (encryption)
    {
        cert = zcert_new();
        assert(cert);
        zyre_set_zcert(self->node, cert);
        zcert_destroy(&cert);
    }
    zyre_set_port(self->node, PEER_DISCOVERY_PORT);
    self->name = strdup(zyre_name(self->node));
    self->group = _group;
    self->group_hash = strndup(_group_hash, 33);
    self->exited = false;
    self->auth_password = peer_md5sum_md5String(_passwd);
    destroy_ptr(_name);
    destroy_ptr(group_hash);

    self->available_peers = zhash_new();
    assert(self->available_peers);
    if (zhash_insert(self->available_peers, zyre_name(self->node), strdup(zyre_uuid(self->node))))
    {
        peer_errno = -PEER_SELF_INSERTION_FAILED;
        goto cleanup_all;
    }
    self->available_uuids = zhash_new();
    assert(self->available_uuids);
    if (zhash_insert(self->available_uuids, zyre_uuid(self->node), strdup(zyre_name(self->node))))
    {
        peer_errno = -PEER_SELF_INSERTION_FAILED;
        goto cleanup_all;
    }
    self->auth_wait_time = PEER_AUTH_TIMEOUT;
    self->blacklist_uuids = zlist_new();
    assert(self->blacklist_uuids);
    self->provisional_peers = zhash_new();
    assert(self->provisional_peers);
    self->peer_retries = zhash_new();
    assert(self->peer_retries);
    self->retry_count = -1;
    self->on_connect_cbs = zhash_new();
    assert(self->on_connect_cbs);
    self->on_connect_cb_args = zhash_new();
    assert(self->on_connect_cb_args);
    self->on_exit_cbs = zhash_new();
    assert(self->on_exit_cbs);
    self->on_exit_cb_args = zhash_new();
    assert(self->on_exit_cb_args);
    self->on_evasive_cbs = zhash_new();
    assert(self->on_evasive_cbs);
    self->on_evasive_cb_args = zhash_new();
    assert(self->on_evasive_cb_args);
    self->on_silent_cbs = zhash_new();
    assert(self->on_silent_cbs);
    self->on_silent_cb_args = zhash_new();
    assert(self->on_silent_cb_args);
    self->on_message_cbs = zhash_new();
    assert(self->on_message_cbs);
    self->on_message_cb_args = zhash_new();
    assert(self->on_message_cb_args);

    self->py_on_connect_cbs = zhash_new();
    assert(self->py_on_connect_cbs);
    self->py_on_exit_cbs = zhash_new();
    assert(self->py_on_exit_cbs);
    self->py_on_evasive_cbs = zhash_new();
    assert(self->py_on_evasive_cbs);
    self->py_on_silent_cbs = zhash_new();
    assert(self->py_on_silent_cbs);
    self->py_on_message_cbs = zhash_new();
    assert(self->py_on_message_cbs);

    peer_errno = PEER_SUCCESS;
    return self;
cleanup_all:
    destroy_ptr(self);
    destroy_ptr(_passwd);
cleanup_group:
    destroy_ptr(group_hash);
    destroy_ptr(_group);
cleanup_name:
    destroy_ptr(_name);
ret_error:
    zcert_destroy(&cert);
    return self;
}

void peer_destroy(peer_t **self_p)
{
    assert(*self_p);
    peer_t *self = *self_p;
    peer_stop(self);
    zyre_destroy(&(self->node));
    zlist_destroy(&(self->blacklist_uuids));
    zhash_destroy(&(self->provisional_peers));
    zhash_destroy(&(self->available_peers));
    zhash_destroy(&(self->available_uuids));
    zhash_destroy(&(self->peer_retries));
    zhash_destroy(&(self->on_connect_cbs));
    zhash_destroy(&(self->on_connect_cb_args));
    zhash_destroy(&(self->on_exit_cbs));
    zhash_destroy(&(self->on_exit_cb_args));
    zhash_destroy(&(self->on_message_cbs));
    zhash_destroy(&(self->on_message_cb_args));
    zhash_destroy(&(self->on_evasive_cbs));
    zhash_destroy(&(self->on_evasive_cb_args));
    zhash_destroy(&(self->on_silent_cbs));
    zhash_destroy(&(self->on_silent_cb_args));

    zhash_destroy(&(self->py_on_connect_cbs));
    zhash_destroy(&(self->py_on_exit_cbs));
    zhash_destroy(&(self->py_on_evasive_cbs));
    zhash_destroy(&(self->py_on_silent_cbs));
    zhash_destroy(&(self->py_on_message_cbs));

    destroy_ptr(self->name);
    destroy_ptr(self->group);
    destroy_ptr(self->group_hash);
    destroy_ptr(self->auth_password);
    destroy_ptr_p(self_p);
}

const char *peer_uuid(peer_t *self)
{
    assert(self);
    assert(self->node);
    return zyre_uuid(self->node);
}

const char *peer_name(peer_t *self)
{
    assert(self);
    assert(self->name);
    return self->name;
}

void peer_set_verbose(peer_t *self)
{
    assert(self);
    assert(self->node);
    self->verbose = true;
    zyre_set_verbose(self->node);
}

int peer_set_port(peer_t *self, int port)
{
    assert(self);
    assert(self->node);
    if ((port < 1000) || (port > 65535))
    {
        peer_errno = -PEER_PORT_RANGE_INVALID;
        self->peer_errno = -PEER_PORT_RANGE_INVALID;
        return -1;
    }
    zyre_set_port(self->node, port);
    peer_errno = PEER_SUCCESS;
    self->peer_errno = -PEER_PORT_RANGE_INVALID;
    return 0;
}

int peer_set_evasive_timeout(peer_t *self, unsigned int interval_ms)
{
    assert(self);
    assert(self->node);
    if (interval_ms > PEER_INTERVAL_MS_MAX) //
    {
        peer_errno = -PEER_INTERVAL_TOO_LARGE;
        self->peer_errno = -PEER_INTERVAL_TOO_LARGE;
        return -1;
    }
    zyre_set_evasive_timeout(self->node, interval_ms);
    peer_errno = PEER_SUCCESS;
    self->peer_errno = PEER_SUCCESS;
    return 0;
}

int peer_set_expired_timeout(peer_t *self, unsigned int interval_ms)
{
    assert(self);
    assert(self->node);
    if (interval_ms > PEER_INTERVAL_MS_MAX) //
    {
        peer_errno = -PEER_INTERVAL_TOO_LARGE;
        self->peer_errno = -PEER_INTERVAL_TOO_LARGE;
        return -1;
    }
    zyre_set_expired_timeout(self->node, interval_ms);
    peer_errno = PEER_SUCCESS;
    self->peer_errno = PEER_SUCCESS;
    return 0;
}

int peer_set_interval(peer_t *self, size_t interval_ms)
{
    assert(self);
    assert(self->node);
    if (interval_ms > PEER_INTERVAL_MS_MAX) //
    {
        peer_errno = -PEER_INTERVAL_TOO_LARGE;
        self->peer_errno = -PEER_INTERVAL_TOO_LARGE;
        return -1;
    }
    zyre_set_interval(self->node, interval_ms);
    peer_errno = PEER_SUCCESS;
    self->peer_errno = PEER_SUCCESS;
    return 0;
}

void peer_set_interface(peer_t *self, const char *value)
{
    assert(self);
    assert(self->node);
    assert(value);
    zyre_set_interface(self->node, value);
}

int peer_set_endpoint(peer_t *self, const char *format, ...)
{
    assert(self);
    assert(self->node);
    assert(format);

    va_list argptr;
    va_start(argptr, format);
    char *string = zsys_vprintf(format, argptr);
    va_end(argptr);

    int rc = zyre_set_endpoint(self->node, "%s", string);
    free(string);
    return rc;
}

void peer_gossip_bind(peer_t *self, const char *format, ...)
{
    assert(self);
    assert(self->node);
    assert(format);

    va_list argptr;
    va_start(argptr, format);
    char *string = zsys_vprintf(format, argptr);
    va_end(argptr);

    zyre_gossip_bind(self->node, "%s", string);
    free(string);
}

void peer_gossip_connect(peer_t *self, const char *format, ...)
{
    assert(self);
    assert(self->node);
    assert(format);

    va_list argptr;
    va_start(argptr, format);
    char *string = zsys_vprintf(format, argptr);
    va_end(argptr);

    zyre_gossip_connect(self->node, "%s", string);
    free(string);
}

int peer_whisper_internal(peer_t *self, const char *peer, const char *internal_message_type, const char *message_type, void *data, size_t data_len)
{
    int rc = -1;

    zmsg_t *msg = zmsg_new();
    if (!msg)
    {
        peer_errno = -PEER_ZMSG_NEW_FAILED;
        self->peer_errno = -PEER_ZMSG_NEW_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, self->group_hash); // somehow group info is not sent when whispering
    if (rc)
    {
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        self->peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, internal_message_type);
    if (rc)
    {
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        self->peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, message_type);
    if (rc)
    {
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        self->peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    if ((data != NULL) && (data_len > 0))
    {
        rc = zmsg_addmem(msg, data, data_len);
        if (rc)
        {
            peer_errno = -PEER_ZMSG_MEM_INSERT_FAILED;
            self->peer_errno = -PEER_ZMSG_MEM_INSERT_FAILED;
            goto clean_msg_type;
        }
    }

    rc = zyre_whisper(self->node, peer, &msg);
    if (rc)
    {
        peer_errno = -PEER_ZYRE_WHISPER_FAILED;
        self->peer_errno = -PEER_ZYRE_WHISPER_FAILED;
    }
clean_msg_type:
    return rc;
}

int peer_whisper(peer_t *self, const char *name, const char *message_type, void *data, size_t data_len)
{
    static char last_name[16] = {
        0x0,
    };
    static char last_peer_name[33] = {
        0x0,
    };
    int rc = -1;

    assert(self);
    assert(self->node);

    if (!_validate_name(self, name))
    {
        return -1;
    }

    rc = _validate_message_type(self, message_type);
    if (!rc)
    {
        return -1;
    }

    char *msg_type = strdup(message_type);
    if (!msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        self->peer_errno = -PEER_STRDUP_FAILED;
        return -1;
    }
    str_to_upper(msg_type);

    if (!data)
    {
        peer_errno = -PEER_MESSAGE_PAYLOAD_NULL;
        self->peer_errno = -PEER_MESSAGE_PAYLOAD_NULL;
        return -1;
    }
    if (data_len == 0)
    {
        peer_errno = -PEER_MESSAGE_PAYLOAD_LENGTH_ZERO;
        self->peer_errno = -PEER_MESSAGE_PAYLOAD_LENGTH_ZERO;
        return -1;
    }

    const char *uuid = NULL;
    if (strncasecmp(last_name, name, PEER_NAME_MAXLEN) == 0) // check name against last name
    {
        uuid = last_peer_name; // if last name is the same as name, UUID is already in last_peer_name
        goto commence;         // commence transmission checks
    }
    else // last name is not this name
    {
        uuid = find_name(self, name); // find UUID corresponding to this name
    }
    if (uuid == NULL) // UUID is NULL, something is wrong!
    {
        peer_errno = -PEER_DESTINATION_PEER_NOT_FOUND;
        self->peer_errno = -PEER_DESTINATION_PEER_NOT_FOUND;
        return -1;
    }
    else
    {
        strncpy(last_name, name, PEER_NAME_MAXLEN); // update name
        strncpy(last_peer_name, uuid, 33);          // update uuid
    }
commence:
    return peer_whisper_internal(self, uuid, EXTERNAL_MESSAGE_STR, message_type, data, data_len);
}

int peer_whispers(peer_t *self, const char *name, const char *message_type, const char *format, ...)
{
    static char last_name[16] = {
        0x0,
    };
    static char last_peer_name[33] = {
        0x0,
    };
    int rc = -1;
    va_list argptr;
    char *string = NULL;

    assert(self);
    assert(self->node);

    if (!_validate_name(self, name))
    {
        return -1;
    }

    rc = _validate_message_type(self, message_type);
    if (!rc)
    {
        return -1;
    }

    char *msg_type = strdup(message_type);
    if (!msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        self->peer_errno = -PEER_STRDUP_FAILED;
        return -1;
    }
    str_to_upper(msg_type);

    const char *uuid = NULL;
    if (strncasecmp(last_name, name, PEER_NAME_MAXLEN) == 0) // check name against last name
    {
        uuid = last_peer_name; // if last name is the same as name, UUID is already in last_peer_name
        goto commence;         // commence transmission checks
    }
    else // last name is not this name
    {
        uuid = find_name(self, name); // find UUID corresponding to this name
    }
    if (uuid == NULL) // UUID is NULL, something is wrong!
    {
        peer_errno = -PEER_DESTINATION_PEER_NOT_FOUND;
        self->peer_errno = -PEER_DESTINATION_PEER_NOT_FOUND;
        return -1;
    }
    else
    {
        strncpy(last_name, name, PEER_NAME_MAXLEN); // update name
        strncpy(last_peer_name, uuid, 33);          // update uuid
    }
commence:
    va_start(argptr, format);
    string = zsys_vprintf(format, argptr);
    va_end(argptr);
    rc = peer_whisper_internal(self, uuid, EXTERNAL_MESSAGE_STR, msg_type, string, strlen(string) + 1);
    if (rc)
    {
        peer_errno = -PEER_ZYRE_WHISPERS_FAILED;
        self->peer_errno = -PEER_ZYRE_WHISPERS_FAILED;
    }
    free(string);
clean_msg_type:
    free(msg_type);
    return rc;
}

int peer_shout(peer_t *self, const char *message_type, void *data, size_t data_len)
{
    int rc = -1;

    assert(self);
    assert(self->node);

    if (!_validate_message_type(self, message_type))
    {
        return -1;
    }

    if (!data)
    {
        peer_errno = -PEER_MESSAGE_PAYLOAD_NULL;
        self->peer_errno = -PEER_MESSAGE_PAYLOAD_NULL;
        return -1;
    }
    if (data_len == 0)
    {
        self->peer_errno = -PEER_MESSAGE_PAYLOAD_LENGTH_ZERO;
        peer_errno = -PEER_MESSAGE_PAYLOAD_LENGTH_ZERO;
        return -1;
    }

    char *msg_type = strdup(message_type);
    if (!msg_type)
    {
        self->peer_errno = -PEER_STRDUP_FAILED;
        peer_errno = -PEER_STRDUP_FAILED;
        return -1;
    }
    str_to_upper(msg_type);

    zmsg_t *msg = zmsg_new();
    if (!msg)
    {
        self->peer_errno = -PEER_ZMSG_NEW_FAILED;
        peer_errno = -PEER_ZMSG_NEW_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, EXTERNAL_MESSAGE_STR);
    if (rc)
    {
        self->peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, msg_type);
    if (rc)
    {
        self->peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addmem(msg, data, data_len);
    if (rc)
    {
        self->peer_errno = -PEER_ZMSG_MEM_INSERT_FAILED;
        peer_errno = -PEER_ZMSG_MEM_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zyre_shout(self->node, self->group_hash, &msg);
    if (rc)
    {
        self->peer_errno = -PEER_ZYRE_SHOUT_FAILED;
        peer_errno = -PEER_ZYRE_SHOUT_FAILED;
    }
clean_msg_type:
    free(msg_type);
    return rc;
}

int peer_shouts(peer_t *self, const char *message_type, const char *format, ...)
{
    int rc = -1;
    va_list argptr;
    char *string = NULL;

    assert(self);
    assert(self->node);

    if (!format)
    {
        peer_errno = -PEER_FORMAT_STR_IS_NULL;
        self->peer_errno = -PEER_FORMAT_STR_IS_NULL;
        return -1;
    }

    if (!_validate_message_type(self, message_type))
    {
        return -1;
    }

    char *msg_type = strdup(message_type);
    if (!msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        self->peer_errno = -PEER_STRDUP_FAILED;
        return -1;
    }
    str_to_upper(msg_type);

    zmsg_t *msg = zmsg_new();
    if (!msg)
    {
        peer_errno = -PEER_ZMSG_NEW_FAILED;
        self->peer_errno = -PEER_ZMSG_NEW_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, "");
    if (rc)
    {
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        self->peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, msg_type);
    if (rc)
    {
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        self->peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    va_start(argptr, format);
    string = zsys_vprintf(format, argptr);
    va_end(argptr);

    rc = peer_shout(self, msg_type, string, strlen(string) + 1);
    if (rc)
    {
        peer_errno = -PEER_ZYRE_SHOUTS_FAILED;
        self->peer_errno = -PEER_ZYRE_SHOUTS_FAILED;
    }
    free(string);
clean_msg_type:
    free(msg_type);
    return rc;
}

zhash_t *peer_list_connected(peer_t *self)
{
    assert(self);
    assert(self->node);
    return self->available_peers;
}

char *peer_get_remote_address(peer_t *self, const char *name)
{
    static char last_name[16] = {
        0x0,
    };
    static char last_peer_name[33] = {
        0x0,
    };
    const char *uuid = NULL;
    char *ret = NULL;

    assert(self);
    assert(self->node);

    if (!validate_name(name))
    {
        uuid = "";
    }

    if (strncasecmp(last_name, name, PEER_NAME_MAXLEN) == 0) // check name against last name
    {
        uuid = last_peer_name; // if last name is the same as name, UUID is already in last_peer_name
        goto commence;         // commence transmission checks
    }
    else // last name is not this name
    {
        uuid = find_name(self, name); // find UUID corresponding to this name
    }
    if (uuid == NULL) // UUID is NULL, something is wrong!
    {
        peer_errno = -PEER_DESTINATION_PEER_NOT_FOUND;
        self->peer_errno = -PEER_DESTINATION_PEER_NOT_FOUND;
        uuid = "";
    }
    else
    {
        strncpy(last_name, name, PEER_NAME_MAXLEN); // update name
        strncpy(last_peer_name, uuid, 33);          // update uuid
    }
commence:
    ret = zyre_peer_address(self->node, uuid);
    if (streq(ret, ""))
    {
        peer_errno = -PEER_ZYRE_PEER_ADDRESS_NOT_FOUND;
        self->peer_errno = -PEER_ZYRE_PEER_ADDRESS_NOT_FOUND;
    }
    else
    {
        peer_errno = PEER_SUCCESS;
        self->peer_errno = PEER_SUCCESS;
    }
    return ret;
}

char *peer_get_remote_header_value(peer_t *self, const char *name)
{
    static char last_name[16] = {
        0x0,
    };
    static char last_peer_name[33] = {
        0x0,
    };
    const char *uuid = NULL;
    char *ret = NULL;

    assert(self);
    assert(self->node);

    if (!validate_name(name))
        uuid = "";

    char *_name = strdup(name);
    if (!_name)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        self->peer_errno = -PEER_STRDUP_FAILED;
        uuid = "";
        _name = strdup(name);
    }
    else
    {
        str_to_upper(_name);
    }

    if (strncasecmp(last_name, name, PEER_NAME_MAXLEN) == 0) // check name against last name
    {
        uuid = last_peer_name; // if last name is the same as name, UUID is already in last_peer_name
        goto commence;         // commence transmission checks
    }
    else // last name is not this name
    {
        uuid = find_name(self, name); // find UUID corresponding to this name
    }
    if (uuid == NULL) // UUID is NULL, something is wrong!
    {
        peer_errno = -PEER_DESTINATION_PEER_NOT_FOUND;
        self->peer_errno = -PEER_DESTINATION_PEER_NOT_FOUND;
        uuid = "";
    }
    else
    {
        strncpy(last_name, name, PEER_NAME_MAXLEN); // update name
        strncpy(last_peer_name, uuid, 33);          // update uuid
    }
commence:
    ret = zyre_peer_header_value(self->node, uuid, _name);
    if (!ret)
    {
        peer_errno = -PEER_ZYRE_PEER_HEADER_VALUE_FAILED;
        self->peer_errno = -PEER_ZYRE_PEER_HEADER_VALUE_FAILED;
    }
    else
    {
        peer_errno = PEER_SUCCESS;
        self->peer_errno = PEER_SUCCESS;
    }
    return ret;
}

void peer_print(peer_t *self)
{
    assert(self);
    assert(self->node);
    zyre_print(self->node);
    printf("-- Break --\n");
    printf("Peer name: %s\n", self->name);
    printf("Group name: %s\n", self->group);
    printf("Public group name: %s\n", self->group_hash);
    printf("Connected peers: ");
    char *name = zhash_first(self->available_peers);
    while (name)
    {
        printf("%s, ", name);
        name = zhash_next(self->available_peers);
    }
    printf("\n");
    printf("\n");
    printf("-- END --\n\n");
}

uint64_t peer_version()
{
    return PEER_VERSION;
}

zyre_t *peer_get_backend(peer_t *self)
{
    assert(self);
    return self->node;
}

void peer_set_evasive_retry_count(peer_t *self, int retry_count)
{
    if (retry_count == 0)
    {
        retry_count = -1;
    }
    if (!self->started)
    {
        self->retry_count = retry_count;
    }
}

void peer_set_silent_eviction(peer_t *self, bool eviction)
{
    if (self->verbose)
    {
        zsys_info("%s> Setting silent eviction from %d to %d.", self->evict_on_silent, eviction);
    }
    self->evict_on_silent = eviction;
}

bool peer_silent_eviction_enabled(peer_t *self)
{
    return self->evict_on_silent;
}

int peer_get_receiver_messages(peer_t *self, int timeout_ms)
{
    zpoller_t *poller = NULL;
    int rc = -1;
    poller = zpoller_new(self->receiver, NULL);
    if (!poller)
    {
        peer_errno = -PEER_COULD_NOT_CREATE_ZPOLLER;
        self->peer_errno = -PEER_COULD_NOT_CREATE_ZPOLLER;
        return -1;
    }
    void *which = zpoller_wait(poller, timeout_ms);
    if (which == self->receiver)
    {
        int status = -PEER_MAX_ERROR;
        rc = zsock_recv(which, "i", &status);
        if (rc)
        {
            zsys_error("%s> Did not receive any status message, what's going on?", self->name);
            assert(false);
        }
        rc = status;
    }
    else if (which == NULL)
    {
        if (zpoller_expired(poller))
        {
            zsys_error("%s> Authentication poller expired.");
            rc = -1;
            peer_errno = -PEER_ZPOLLER_TIMED_OUT;
            self->peer_errno = -PEER_ZPOLLER_TIMED_OUT;
        }
        else if (zpoller_terminated(poller))
        {
            zsys_error("%s> Authentication poller was killed! Error!", self->name);
            assert(false);
        }
    }
    peer_errno = PEER_SUCCESS;
    self->peer_errno = PEER_SUCCESS;
    zpoller_destroy(&poller);
    return rc;
}

int peer_start(peer_t *self)
{
    assert(self);
    assert(self->node);
    int rc = 0;
    zpoller_t *poller = NULL;
    assert(!zhash_insert(self->provisional_peers, self->name, strdup(zyre_uuid(self->node))));
    self->receiver = zactor_new(receiver_actor, self);
    if (!self->callback_driver)
    {
        peer_errno = -PEER_RECEIVER_FAILED;
        self->peer_errno = -PEER_RECEIVER_FAILED;
        goto errored;
    }

    if (zsock_wait(self->receiver))
    {
        peer_errno = -PEER_RECEIVER_FAILED;
        self->peer_errno = -PEER_RECEIVER_FAILED;
        goto errored_destroy;
    }
    poller = zpoller_new(self->receiver, NULL);
    assert(poller);

    void *which = zpoller_wait(poller, self->auth_wait_time + 1000);
    if (which == self->receiver)
    {
        int status = -PEER_MAX_ERROR;
        rc = zsock_recv(which, "i", &status);
        if (rc)
        {
            zsys_error("%s> Did not receive any status message, what's going on?", self->name);
            assert(false);
        }
        if (status == -PEER_EXISTS)
        {
            zsys_error("Peer name %s already exists, exiting...", self->name);
            rc = -1;
            peer_errno = -PEER_EXISTS;
            self->peer_errno = -PEER_EXISTS;
            goto errored_zpoller_destroy;
        }
        else if (status == -PEER_AUTH_FAILED)
        {
            zsys_error("%s> Authentication rejected!", self->name);
            rc = -1;
            peer_errno = -PEER_AUTH_FAILED;
            self->peer_errno = -PEER_AUTH_FAILED;
            goto errored_zpoller_destroy;
        }
        else if (status == PEER_SUCCESS)
        {
            if (self->verbose)
            {
                zsys_info("%s> Successfully authenticated and joined the network.", self->name);
            }
            rc = PEER_SUCCESS;
        }
    }
    else if (which == NULL)
    {
        if (zpoller_expired(poller))
        {
            zsys_error("%s> Authentication poller expired.");
            rc = -1;
            peer_errno = -PEER_AUTH_REQUEST_TIMEDOOUT;
            self->peer_errno = -PEER_AUTH_REQUEST_TIMEDOOUT;
            goto errored_zpoller_destroy;
        }
        else if (zpoller_terminated(poller))
        {
            zsys_error("%s> Authentication poller was killed! Error!", self->name);
            assert(false);
        }
    }
    self->started = true;
    peer_errno = PEER_SUCCESS;
    self->peer_errno = PEER_SUCCESS;
    zpoller_destroy(&poller);
    return rc;
errored_zpoller_destroy:
    zpoller_destroy(&poller);
errored_destroy:
    zactor_destroy(&self->receiver);
errored:
    return rc;
}

void peer_stop(peer_t *self)
{
    assert(self);
    assert(self->node);

    if (!self->exited)
    {
        zsock_send(self->receiver, "s", "$TERM");
        zsock_wait(self->receiver);
    }
    zactor_destroy(&self->receiver);
}

int peer_on_message(peer_t *self, const char *name, const char *message_type, peer_callback_t callback, void *local_args)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->on_message_cb_args);
    assert(self->on_message_cbs);

    char hash_name[PEER_NAME_MAXLEN + PEER_MESSAGETYPE_MAXLEN + 2] = {
        0x0,
    };

    if (!validate_name(name))
    {
        return -1;
    }

    if (!validate_message_type(message_type))
    {
        return -1;
    }

    char *_name = strdup(name);
    if (!_name)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        return -1;
    }
    str_to_upper(_name);

    char *_msg_type = strdup(message_type);
    if (!_msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        goto cleanup_name;
    }
    str_to_upper(_msg_type);
    int len = snprintf(hash_name, sizeof(hash_name), "%s.%s", _msg_type, _name);
    if (len != strlen(_msg_type) + strlen(_name) + 1)
    {
        peer_errno = -PEER_STRCONCAT_FAILED;
        goto cleanup_msg_type;
    }

    zhash_delete(self->on_message_cbs, hash_name);
    zhash_delete(self->on_message_cb_args, hash_name);

    if ((rc = zhash_insert(self->on_message_cbs, hash_name, callback)))
    {
        peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        goto cleanup_msg_type;
    }
    if ((rc = zhash_insert(self->on_message_cb_args, hash_name, local_args)))
    {
        zhash_delete(self->on_message_cbs, hash_name);
        peer_errno = -PEER_CALLBACK_LOCALARG_INSERTION_FAILED;
        goto cleanup_msg_type;
    }
    peer_errno = PEER_SUCCESS;
cleanup_msg_type:
    destroy_ptr(_msg_type);
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_disable_on_message(peer_t *self, const char *name, const char *message_type)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->on_message_cb_args);
    assert(self->on_message_cbs);

    char hash_name[PEER_NAME_MAXLEN + PEER_MESSAGETYPE_MAXLEN + 2] = {
        0x0,
    };

    if (!validate_name(name))
    {
        return -1;
    }

    if (!validate_message_type(message_type))
    {
        return -1;
    }

    char *_name = strdup(name);
    if (!_name)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        return -1;
    }
    str_to_upper(_name);

    char *_msg_type = strdup(message_type);
    if (!_msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        goto cleanup_name;
    }
    str_to_upper(_msg_type);

    int len = snprintf(hash_name, sizeof(hash_name), "%s.%s", _msg_type, _name);
    if (len != strlen(_msg_type) + strlen(_name) + 1) // should this be an assert?
    {
        peer_errno = -PEER_STRCONCAT_FAILED;
        goto cleanup_msg_type;
    }

    // 1. Check if message type at all registered
    if (!zhash_exists(self->on_connect_cbs, hash_name))
    {
        peer_errno = -PEER_MESSAGE_TYPE_NOT_REGISTERED;
        goto cleanup_msg_type;
    }

    zhash_delete(self->on_connect_cbs, hash_name);
    zhash_delete(self->on_connect_cb_args, hash_name);
    peer_errno = PEER_SUCCESS;
    rc = 0;
cleanup_msg_type:
    destroy_ptr(_msg_type);
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_on_connect(peer_t *self, const char *peer, peer_callback_t _Nullable callback, void *local_args)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->on_connect_cbs);
    assert(self->on_connect_cb_args);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!validate_name(peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        self->all_on_connect_cb = callback;
        self->all_on_connect_cb_args = local_args;
        peer_errno = PEER_SUCCESS;
        rc = 0;
        goto cleanup_name;
    }
    assert(_name);

    if (zhash_exists(self->on_connect_cbs, _name)) // already exists
    {
        zhash_delete(self->on_connect_cbs, _name);
        zhash_delete(self->on_connect_cb_args, _name);
    }

    if ((rc = zhash_insert(self->on_connect_cbs, _name, callback)))
    {
        peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        goto cleanup_name;
    }

    if ((rc = zhash_insert(self->on_connect_cb_args, _name, local_args)))
    {
        peer_errno = -PEER_CALLBACK_LOCALARG_INSERTION_FAILED;
        zhash_delete(self->on_connect_cbs, _name);
        goto cleanup_name;
    }
    peer_errno = PEER_SUCCESS;
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_disable_on_connect(peer_t *self, const char *peer)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->on_connect_cbs);
    assert(self->on_connect_cb_args);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!validate_name(peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        self->all_on_connect_cb = NULL;
        self->all_on_connect_cb_args = NULL;
        peer_errno = PEER_SUCCESS;
        rc = 0;
        goto cleanup_name;
    }
    assert(_name);

    if (zhash_exists(self->on_connect_cbs, _name)) // already exists
    {
        zhash_delete(self->on_connect_cbs, _name);
        zhash_delete(self->on_connect_cb_args, _name);
        peer_errno = PEER_SUCCESS;
        rc = 0;
    }
    else
    {
        peer_errno = -PEER_CALLBACK_DOES_NOT_EXIST;
        rc = -1;
    }
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_on_disconnect(peer_t *self, const char *peer, peer_callback_t _Nullable callback, void *local_args)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->on_exit_cbs);
    assert(self->on_exit_cb_args);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!validate_name(peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        self->all_on_disconnect_cb = callback;
        self->all_on_disconnect_cb_args = local_args;
        peer_errno = PEER_SUCCESS;
        rc = 0;
        goto cleanup_name;
    }
    assert(_name);

    if (zhash_exists(self->on_exit_cbs, _name)) // already exists
    {
        zhash_delete(self->on_exit_cbs, _name);
        zhash_delete(self->on_exit_cb_args, _name);
    }

    if ((rc = zhash_insert(self->on_exit_cbs, _name, callback)))
    {
        peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        goto cleanup_name;
    }

    if ((rc = zhash_insert(self->on_exit_cb_args, _name, local_args)))
    {
        peer_errno = -PEER_CALLBACK_LOCALARG_INSERTION_FAILED;
        zhash_delete(self->on_exit_cbs, _name);
        goto cleanup_name;
    }
    peer_errno = PEER_SUCCESS;
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_disable_on_disconnect(peer_t *self, const char *peer)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->on_exit_cbs);
    assert(self->on_exit_cb_args);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!validate_name(peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        self->all_on_disconnect_cb = NULL;
        self->all_on_disconnect_cb_args = NULL;
        peer_errno = PEER_SUCCESS;
        rc = 0;
        goto cleanup_name;
    }
    assert(_name);

    if (zhash_exists(self->on_exit_cbs, _name)) // already exists
    {
        zhash_delete(self->on_exit_cbs, _name);
        zhash_delete(self->on_exit_cb_args, _name);
        peer_errno = PEER_SUCCESS;
        rc = 0;
    }
    else
    {
        peer_errno = -PEER_CALLBACK_DOES_NOT_EXIST;
        rc = -1;
    }
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_on_evasive(peer_t *self, const char *peer, peer_callback_t callback, void *local_args)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->on_evasive_cbs);
    assert(self->on_evasive_cb_args);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!validate_name(peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        _name = self->name;
    }
    assert(_name);

    if (zhash_exists(self->on_evasive_cbs, _name)) // already exists
    {
        zhash_delete(self->on_evasive_cbs, _name);
        zhash_delete(self->on_evasive_cb_args, _name);
    }

    if ((rc = zhash_insert(self->on_evasive_cbs, _name, callback)))
    {
        peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        goto cleanup_name;
    }

    if ((rc = zhash_insert(self->on_evasive_cb_args, _name, local_args)))
    {
        peer_errno = -PEER_CALLBACK_LOCALARG_INSERTION_FAILED;
        zhash_delete(self->on_evasive_cbs, _name);
        goto cleanup_name;
    }
    peer_errno = PEER_SUCCESS;
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_disable_on_evasive(peer_t *self, const char *peer)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->on_evasive_cbs);
    assert(self->on_evasive_cb_args);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!validate_name(peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        _name = self->name;
    }
    assert(_name);

    if (zhash_exists(self->on_evasive_cbs, _name)) // already exists
    {
        zhash_delete(self->on_evasive_cbs, _name);
        zhash_delete(self->on_evasive_cb_args, _name);
        peer_errno = PEER_SUCCESS;
        rc = 0;
    }
    else
    {
        peer_errno = -PEER_CALLBACK_DOES_NOT_EXIST;
        rc = -1;
    }
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_on_silent(peer_t *self, const char *peer, peer_callback_t callback, void *local_args)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->on_silent_cbs);
    assert(self->on_silent_cb_args);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!validate_name(peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        _name = self->name;
    }
    assert(_name);

    if (zhash_exists(self->on_silent_cbs, _name)) // already exists
    {
        zhash_delete(self->on_silent_cbs, _name);
        zhash_delete(self->on_silent_cb_args, _name);
    }

    if ((rc = zhash_insert(self->on_silent_cbs, _name, callback)))
    {
        peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        goto cleanup_name;
    }

    if ((rc = zhash_insert(self->on_silent_cb_args, _name, local_args)))
    {
        peer_errno = -PEER_CALLBACK_LOCALARG_INSERTION_FAILED;
        zhash_delete(self->on_silent_cbs, _name);
        goto cleanup_name;
    }
    peer_errno = PEER_SUCCESS;
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_disable_on_silent(peer_t *self, const char *peer)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->on_silent_cbs);
    assert(self->on_silent_cb_args);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!validate_name(peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        _name = self->name;
    }
    assert(_name);

    if (zhash_exists(self->on_silent_cbs, _name)) // already exists
    {
        zhash_delete(self->on_silent_cbs, _name);
        zhash_delete(self->on_silent_cb_args, _name);
        peer_errno = PEER_SUCCESS;
        rc = 0;
    }
    else
    {
        peer_errno = -PEER_CALLBACK_DOES_NOT_EXIST;
        rc = -1;
    }
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

void peer_py_destroy(void **ptr)
{
    peer_destroy((peer_t **)ptr);
}

char *peer_py_list_connected(peer_t *self)
{
    assert(self);
    assert(self->node);
    zhash_t *hash = zhash_dup(peer_list_connected(self));
    char *out = NULL;
    char *uuid = NULL;
    for (uuid = zhash_first(hash); uuid; uuid = zhash_next(hash))
    {
        if (out)
        {
            out = zsys_sprintf("%s,%s:%s", out, zhash_cursor(hash), uuid);
        }
        else
        {
            out = zsys_sprintf("%s:%s", zhash_cursor(hash), uuid);
        }
    }
    zhash_destroy(&hash);
    return out;
}

int peer_py_on_message(peer_t *self, const char *name, const char *message_type, peer_py_callback_t callback)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->py_on_message_cbs);

    char hash_name[PEER_NAME_MAXLEN + PEER_MESSAGETYPE_MAXLEN + 2] = {
        0x0,
    };

    if (!_validate_name(self, name))
    {
        return -1;
    }

    if (!_validate_message_type(self, message_type))
    {
        return -1;
    }

    char *_name = strdup(name);
    if (!_name)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        self->peer_errno = -PEER_STRDUP_FAILED;
        return -1;
    }
    str_to_upper(_name);

    char *_msg_type = strdup(message_type);
    if (!_msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        self->peer_errno = -PEER_STRDUP_FAILED;
        goto cleanup_name;
    }
    str_to_upper(_msg_type);
    int len = snprintf(hash_name, sizeof(hash_name), "%s.%s", _msg_type, _name);
    if (len != strlen(_msg_type) + strlen(_name) + 1)
    {
        peer_errno = -PEER_STRCONCAT_FAILED;
        self->peer_errno = -PEER_STRCONCAT_FAILED;
        goto cleanup_msg_type;
    }

    zhash_delete(self->py_on_message_cbs, hash_name);

    if ((rc = zhash_insert(self->py_on_message_cbs, hash_name, callback)))
    {
        peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        self->peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        goto cleanup_msg_type;
    }
    peer_errno = PEER_SUCCESS;
    self->peer_errno = PEER_SUCCESS;
cleanup_msg_type:
    destroy_ptr(_msg_type);
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_py_disable_on_message(peer_t *self, const char *name, const char *message_type)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->py_on_message_cbs);

    char hash_name[PEER_NAME_MAXLEN + PEER_MESSAGETYPE_MAXLEN + 2] = {
        0x0,
    };

    if (!_validate_name(self, name))
    {
        return -1;
    }

    if (!_validate_message_type(self, message_type))
    {
        return -1;
    }

    char *_name = strdup(name);
    if (!_name)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        self->peer_errno = -PEER_STRDUP_FAILED;
        return -1;
    }
    str_to_upper(_name);

    char *_msg_type = strdup(message_type);
    if (!_msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        self->peer_errno = -PEER_STRDUP_FAILED;
        goto cleanup_name;
    }
    str_to_upper(_msg_type);

    int len = snprintf(hash_name, sizeof(hash_name), "%s.%s", _msg_type, _name);
    if (len != strlen(_msg_type) + strlen(_name) + 1) // should this be an assert?
    {
        peer_errno = -PEER_STRCONCAT_FAILED;
        self->peer_errno = -PEER_STRCONCAT_FAILED;
        goto cleanup_msg_type;
    }

    // 1. Check if message type at all registered
    if (!zhash_exists(self->py_on_connect_cbs, hash_name))
    {
        peer_errno = -PEER_MESSAGE_TYPE_NOT_REGISTERED;
        self->peer_errno = -PEER_MESSAGE_TYPE_NOT_REGISTERED;
        goto cleanup_msg_type;
    }

    zhash_delete(self->py_on_connect_cbs, hash_name);
    peer_errno = PEER_SUCCESS;
    self->peer_errno = PEER_SUCCESS;
    rc = 0;
cleanup_msg_type:
    destroy_ptr(_msg_type);
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_py_on_connect(peer_t *self, const char *peer, peer_py_callback_t _Nullable callback)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->py_on_connect_cbs);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!_validate_name(self, peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            self->peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        self->py_all_on_connect_cb = callback;
        if (self->verbose)
        {
            zsys_info("%s> Peer on connect registered: ALL, %p | %p", self->name, callback, self->py_all_on_connect_cb);
        }
        peer_errno = PEER_SUCCESS;
        self->peer_errno = PEER_SUCCESS;
        rc = 0;
        goto cleanup_name;
    }
    assert(_name);

    if (zhash_exists(self->py_on_connect_cbs, _name)) // already exists
    {
        zhash_delete(self->py_on_connect_cbs, _name);
    }

    if ((rc = zhash_insert(self->py_on_connect_cbs, _name, callback)))
    {
        peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        self->peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        goto cleanup_name;
    }

    zsys_info("%s> Inserted %p, got %p (%s)", self->name, callback, zhash_lookup(self->py_on_connect_cbs, _name), _name);

    if (self->verbose)
    {
        zsys_info("%s> Peer on connect registered: %s (%s), %p | %p", self->name, peer, _name, callback, zhash_lookup(self->py_on_connect_cbs, _name));
    }

    peer_errno = PEER_SUCCESS;
    self->peer_errno = PEER_SUCCESS;
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_py_disable_on_connect(peer_t *self, const char *peer)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->py_on_connect_cbs);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!_validate_name(self, peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            self->peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        self->py_all_on_connect_cb = NULL;
        peer_errno = PEER_SUCCESS;
        self->peer_errno = PEER_SUCCESS;
        rc = 0;
        goto cleanup_name;
    }
    assert(_name);

    if (zhash_exists(self->py_on_connect_cbs, _name)) // already exists
    {
        zhash_delete(self->py_on_connect_cbs, _name);
        peer_errno = PEER_SUCCESS;
        self->peer_errno = PEER_SUCCESS;
        rc = 0;
    }
    else
    {
        peer_errno = -PEER_CALLBACK_DOES_NOT_EXIST;
        self->peer_errno = -PEER_CALLBACK_DOES_NOT_EXIST;
        rc = -1;
    }
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_py_on_disconnect(peer_t *self, const char *peer, peer_py_callback_t _Nullable callback)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->py_on_exit_cbs);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!_validate_name(self, peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            self->peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        self->py_all_on_exit_cb = callback;
        peer_errno = PEER_SUCCESS;
        self->peer_errno = PEER_SUCCESS;
        rc = 0;
        goto cleanup_name;
    }
    assert(_name);

    if (zhash_exists(self->py_on_exit_cbs, _name)) // already exists
    {
        zhash_delete(self->py_on_exit_cbs, _name);
    }

    if ((rc = zhash_insert(self->py_on_exit_cbs, _name, callback)))
    {
        peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        self->peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        goto cleanup_name;
    }

    peer_errno = PEER_SUCCESS;
    self->peer_errno = PEER_SUCCESS;
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_py_disable_on_disconnect(peer_t *self, const char *peer)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->py_on_exit_cbs);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!_validate_name(self, peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            self->peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        self->py_all_on_exit_cb = NULL;
        peer_errno = PEER_SUCCESS;
        self->peer_errno = PEER_SUCCESS;
        rc = 0;
        goto cleanup_name;
    }
    assert(_name);

    if (zhash_exists(self->py_on_exit_cbs, _name)) // already exists
    {
        zhash_delete(self->py_on_exit_cbs, _name);
        peer_errno = PEER_SUCCESS;
        self->peer_errno = PEER_SUCCESS;
        rc = 0;
    }
    else
    {
        peer_errno = -PEER_CALLBACK_DOES_NOT_EXIST;
        self->peer_errno = -PEER_CALLBACK_DOES_NOT_EXIST;
        rc = -1;
    }
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_py_on_evasive(peer_t *self, const char *peer, peer_py_callback_t callback)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->py_on_evasive_cbs);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!_validate_name(self, peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            self->peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        _name = self->name;
    }
    assert(_name);

    if (zhash_exists(self->py_on_evasive_cbs, _name)) // already exists
    {
        zhash_delete(self->py_on_evasive_cbs, _name);
    }

    if ((rc = zhash_insert(self->py_on_evasive_cbs, _name, callback)))
    {
        peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        self->peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        goto cleanup_name;
    }

    peer_errno = PEER_SUCCESS;
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_py_disable_on_evasive(peer_t *self, const char *peer)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->py_on_evasive_cbs);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!_validate_name(self, peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            self->peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        _name = self->name;
    }
    assert(_name);

    if (zhash_exists(self->py_on_evasive_cbs, _name)) // already exists
    {
        zhash_delete(self->py_on_evasive_cbs, _name);
        peer_errno = PEER_SUCCESS;
        rc = 0;
    }
    else
    {
        peer_errno = -PEER_CALLBACK_DOES_NOT_EXIST;
        rc = -1;
    }
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_py_on_silent(peer_t *self, const char *peer, peer_py_callback_t callback)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->py_on_silent_cbs);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!_validate_name(self, peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            self->peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        _name = self->name;
    }
    assert(_name);

    if (zhash_exists(self->py_on_silent_cbs, _name)) // already exists
    {
        zhash_delete(self->py_on_silent_cbs, _name);
    }

    if ((rc = zhash_insert(self->py_on_silent_cbs, _name, callback)))
    {
        peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        self->peer_errno = -PEER_CALLBACK_INSERTION_FAILED;
        goto cleanup_name;
    }

    peer_errno = PEER_SUCCESS;
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_py_disable_on_silent(peer_t *self, const char *peer)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->py_on_silent_cbs);

    char *_name = NULL;

    if (peer) // non-NULL
    {
        if (!_validate_name(self, peer))
        {
            return -1;
        }

        _name = strdup(peer);
        if (!_name)
        {
            peer_errno = -PEER_STRDUP_FAILED;
            self->peer_errno = -PEER_STRDUP_FAILED;
            return -1;
        }
        str_to_upper(_name);
    }
    else
    {
        _name = self->name;
    }
    assert(_name);

    if (zhash_exists(self->py_on_silent_cbs, _name)) // already exists
    {
        zhash_delete(self->py_on_silent_cbs, _name);
        peer_errno = PEER_SUCCESS;
        rc = 0;
    }
    else
    {
        peer_errno = -PEER_CALLBACK_DOES_NOT_EXIST;
        rc = -1;
    }
cleanup_name:
    destroy_ptr(_name);
    return rc;
}

int peer_py_errno(peer_t *self)
{
    assert(self);
    return self->peer_errno;
}

// ------------------ END CLASS FUNCTIONS -------------------- //

// ------------------ SELF TEST FUNCTIONS -------------------- //

static void __peernet_on_connect_demo(peer_t *self, const char *message_type, const char *peer, void *local, void *remote, size_t len)
{
    printf("\n\nIn connect callback of %s: %s connected\n\n", peer_name(self), peer);
}

static void __peernet_on_exit_demo(peer_t *self, const char *message_type, const char *peer, void *local, void *remote, size_t len)
{
    printf("\n\nIn disconnect callback of %s: %s disconnected\n\n", peer_name(self), peer);
}

static void __peernet_on_message_demo(peer_t *self, const char *message_type, const char *peer, void *local, void *remote, size_t len)
{
    char *msg = (char *)remote;
    printf("\n\nIn message callback of %s (type %s): %s says %s\n\n", peer_name(self), message_type, peer, msg);
}

static void __peernet_on_evasive_demo(peer_t *self, const char *message_type, const char *peer, void *local, void *remote, size_t len)
{
    printf("\n\nIn evasive callback of %s: %s evading\n\n", peer_name(self), peer);
}

void peer_test(bool verbose)
{
    peer_t *peer_a = peer_new("peer_a", NULL, "password", true);
    peer_t *peer_b = peer_new("peer_b", NULL, "password", true);
    peer_set_evasive_retry_count(peer_a, 2);
    assert(peer_a);
    assert(peer_b);
    if (verbose)
    {
        peer_set_verbose(peer_a);
        peer_set_verbose(peer_b);
    }
    if (peer_on_connect(peer_a, peer_name(peer_b), &__peernet_on_connect_demo, NULL))
    {
        printf("Error: %s (%d)\n", peer_strerror(peer_errno), peer_errno);
    }
    assert(!peer_on_disconnect(peer_b, peer_name(peer_a), &__peernet_on_exit_demo, NULL));
    assert(!peer_on_message(peer_a, peer_name(peer_b), "CHAT", &__peernet_on_message_demo, NULL));
    assert(!peer_on_evasive(peer_a, peer_name(peer_b), &__peernet_on_evasive_demo, NULL));
    assert(!peer_start(peer_a));
    printf("Peer A started\n");
    zclock_sleep(100);
    assert(!peer_start(peer_b));
    printf("Peer B started\n");
    zclock_sleep(1000);
    assert(!peer_whispers(peer_b, peer_name(peer_a), "CHAT", "Hello, %s! I am %s, nice to meet you!", peer_name(peer_a), peer_name(peer_b)));
    zclock_sleep(1000);
    peer_destroy(&peer_a);
    zclock_sleep(500);
    peer_destroy(&peer_b);
}

// ------------------ END SELF TEST FUNCTIONS -------------------- //