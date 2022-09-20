/**
 * @file peernet.c
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief
 * @version 0.1
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
#include "utilities/md5sum.h"

#define eprintlf(fmt, ...)                                                      \
    {                                                                           \
        fprintf(stderr, "%s,%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__); \
        fflush(stderr);                                                         \
    }

#define CALLBACK_CMD_STR "CALLBACK"
#define CALLBACK_CONNECT_STR "CONNECT"
#define CALLBACK_DISCONNECT_STR "LEAVE"
#define CALLBACK_MESSAGE_STR "MESSAGE"
#define INTERNAL_MESSAGE_STR "INTERNAL_MSG"
#define EXTERNAL_MESSAGE_STR "EXTERNAL_MSG"

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
    "Peer receiver initialization failed"                   // 45
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
    bool exited;
    bool verbose;
    peer_callback_t self_on_connect_cb;
    void *self_on_connect_cb_args;
    peer_callback_t self_on_exit_cb;
    void *self_on_exit_cb_args;
    zhash_t *available_peers;    // zhash of peers, keyed by name
    zhash_t *available_uuids;    // zhash of peers, keyed by uuid
    zhash_t *on_connect_cbs;     // zhash of callback fcns, keyed by name
    zhash_t *on_connect_cb_args; // zhash of callback fcn args, keyed by name
    zhash_t *on_exit_cbs;        // zhash of callback fcns, keyed by name
    zhash_t *on_exit_cb_args;    // zhash of callback fcns, keyed by name
    zhash_t *on_message_cbs;     // callback functions keyed by message type
    zhash_t *on_message_cb_args; // callback function args keyed by message type
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

static inline void str_to_lower(char *name)
{
    char *s = name;
    while (*s)
    {
        *s = tolower((unsigned char)*s);
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

    str_to_lower(_name);

    const char *uuid = zhash_lookup(self->available_peers, _name);
    destroy_ptr(_name);

    return uuid;
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
                peer_callback_t cb = NULL;
                void *local_args = NULL;
                void *remote_args = NULL;
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
                    if (!zhash_exists(self->on_connect_cbs, remote_name))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Connect callback for %s not registered.", remote_name);
                        }
                        goto loop_reset;
                    }
                    if (!zhash_exists(self->on_connect_cb_args, remote_name))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Callback local argument from %s not registered.", remote_name);
                        }
                        zhash_delete(self->on_connect_cbs, remote_name);
                        goto loop_reset;
                    }
                    cb = zhash_lookup(self->on_connect_cbs, remote_name);
                    local_args = zhash_lookup(self->on_connect_cb_args, remote_name);
                }
                else if (streq(callback_type, CALLBACK_DISCONNECT_STR)) // for on_disconnect calls
                {
                    if (!zhash_exists(self->on_exit_cbs, remote_name))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Disconnect callback for %s not registered.", remote_name);
                        }
                        goto loop_reset;
                    }
                    if (!zhash_exists(self->on_exit_cb_args, remote_name))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Disconnect callback local argument for %s not registered.", remote_name);
                        }
                        zhash_delete(self->on_exit_cbs, remote_name);
                        goto loop_reset;
                    }
                    cb = zhash_lookup(self->on_exit_cbs, remote_name);
                    local_args = zhash_lookup(self->on_exit_cb_args, remote_name);
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
                    if (!zhash_exists(self->on_message_cbs, hash))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Callback for %s from %s not registered.", message_type, remote_name);
                        }
                        goto loop_reset;
                    }
                    if (!zhash_exists(self->on_message_cb_args, hash))
                    {
                        if (self->verbose)
                        {
                            zsys_error("Callback Actor: Callback local argument for %s from %s not registered.", message_type, remote_name);
                        }
                        zhash_delete(self->on_message_cbs, hash);
                        goto loop_reset;
                    }
                    cb = zhash_lookup(self->on_message_cbs, hash);
                    local_args = zhash_lookup(self->on_message_cb_args, hash);
                    remote_args = zframe_data(frame);
                }
                else
                {
                    if (strlen(callback_type) > 50)
                        callback_type[51] = '\0'; // limit length
                    zsys_error("Callback Actor: Unknown callback type %s.", (callback_type));
                    goto loop_reset;
                }
                // 4. Execute the callback function
                if (self->verbose)
                {
                    zsys_info("Executing callback function at %p.", cb);
                }
                // zsock_send(pipe, "i", executed++);
                if (cb)
                {
                    cb(self, message_type, remote_name, local_args, remote_args);
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
    assert(!zsock_signal(pipe, -local_errno));    // return error message to caller
    return;
}

static void receiver_actor(zsock_t *pipe, void *_args) // Forward declaration.
{
    struct _peer_t *self = (peer_t *)_args;
    int local_errno = PEER_SUCCESS;
    zyre_t *node = self->node;
    int rc = 0;
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
    while (!terminated)
    {
        void *which = zpoller_wait(poller, -1);
        if (which == pipe) // do not really expect too many pipe messages
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
                if (streq(message_type, "NAME_CONFLICT_EVICT"))
                {
                    zsock_send(pipe, "i", -PEER_EXISTS);
                    terminated = true;
                }
                else if (streq(message_type, "NAME_OKAY"))
                {
                    zsock_send(pipe, "i", PEER_SUCCESS);
                }
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
                    if (!zhash_insert(self->available_peers, name, strdup(uuid))) // peer name not already in available peers list
                    {
                        zhash_insert(self->available_uuids, uuid, strdup(name)); // update inverse list as well
                        if (self->verbose)
                        {
                            zsys_info("Peer name OK: %s, sending name induction message to %s!", name, uuid);
                        }
                        rc = peer_whisper_internal(self, uuid, INTERNAL_MESSAGE_STR, "NAME_OKAY", NULL, 0);
                        if (rc)
                        {
                            zsys_error("Peer name OK: %s, could not send message to %s!", name, uuid);
                        }
                        zmsg_t *callback_msg = zmsg_new();
                        if (!callback_msg)
                        {
                            zsys_error("Could not allocate memory to request callback execution.");
                        }
                        else
                        {
                            zmsg_addstr(callback_msg, CALLBACK_CMD_STR);
                            zmsg_addstr(callback_msg, CALLBACK_CONNECT_STR);
                            zmsg_addstr(callback_msg, "");   // message_type
                            zmsg_addstr(callback_msg, name); // peer name
                            if (self->verbose)
                            {
                                zsys_info("To Callback: %s %s %s %s", CALLBACK_CMD_STR, CALLBACK_CONNECT_STR, "", name);
                            }
                            zmsg_send(&callback_msg, self->callback_driver);
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
                if (self->verbose)
                {
                    zsys_info("%s[%s] has left [%s]\n", name, uuid, in_our_group == true ? self->group : group);
                }
                if (in_our_group) // in our group
                {
                    // check if UUID of leaving is in available uuids
                    if (zhash_lookup(self->available_uuids, uuid))
                    {
                        zhash_delete(self->available_peers, name);
                        zhash_delete(self->available_uuids, uuid);
                        if (self->verbose)
                        {
                            zsys_info("Peer name %s [%s] leaving.", name, uuid);
                        }
                        zmsg_t *callback_msg = zmsg_new();
                        if (!callback_msg)
                        {
                            zsys_error("Could not allocate memory to request callback execution.");
                        }
                        else
                        {
                            zmsg_addstr(callback_msg, CALLBACK_CMD_STR);
                            zmsg_addstr(callback_msg, CALLBACK_DISCONNECT_STR);
                            zmsg_addstr(callback_msg, "");   // message_type
                            zmsg_addstr(callback_msg, name); // peer nam
                            if (self->verbose)
                            {
                                zsys_info("To Callback: %s %s %s %s", CALLBACK_CMD_STR, CALLBACK_DISCONNECT_STR, "", name);
                            }
                            zmsg_send(&callback_msg, self->callback_driver);
                        }
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
                            zsys_info("To Callback: %s %s %s %s", CALLBACK_CMD_STR, CALLBACK_CONNECT_STR, "", name);
                        }
                        zmsg_send(&callback_msg, self->callback_driver);
                    }
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
    zyre_stop(self->node);
    zclock_sleep(100);
    zsock_signal(pipe, PEER_SUCCESS);
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

peer_t *peer_new(const char *name, const char *group, bool encryption)
{
    peer_t *self = NULL;
    char *_name = NULL, *_group = NULL, _group_hash[33] = {
                                            0x0,
                                        };
    uint8_t *group_hash = NULL;
    zcert_t *cert = NULL;
    if (encryption)
    {
        cert = zcert_new();
        assert(cert);
    }
    // 1. Check name
    int rc = validate_name(name);
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
    str_to_lower(_group);
    _name = strdup(name);
    assert(_name);
    str_to_lower(_name);
    // 2a. Create the hash
    group_hash = md5String(_group);
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
        zyre_set_zcert(self->node, cert);
        zcert_destroy(&cert);
    }
    self->name = strdup(zyre_name(self->node));
    self->group = _group;
    self->group_hash = strndup(_group_hash, 33);
    self->exited = false;
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
    self->on_connect_cbs = zhash_new();
    assert(self->on_connect_cbs);
    self->on_connect_cb_args = zhash_new();
    assert(self->on_connect_cb_args);
    self->on_exit_cbs = zhash_new();
    assert(self->on_exit_cbs);
    self->on_exit_cb_args = zhash_new();
    assert(self->on_exit_cb_args);
    self->on_message_cbs = zhash_new();
    assert(self->on_message_cbs);
    self->on_message_cb_args = zhash_new();
    assert(self->on_message_cb_args);

    peer_errno = PEER_SUCCESS;
    return self;
cleanup_all:
    destroy_ptr(self);
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
    zhash_destroy(&(self->available_peers));
    zhash_destroy(&(self->available_uuids));
    zhash_destroy(&(self->on_connect_cbs));
    zhash_destroy(&(self->on_connect_cb_args));
    zhash_destroy(&(self->on_exit_cbs));
    zhash_destroy(&(self->on_exit_cb_args));
    zhash_destroy(&(self->on_message_cbs));
    zhash_destroy(&(self->on_message_cb_args));
    destroy_ptr(self->name);
    destroy_ptr(self->group);
    destroy_ptr(self->group_hash);
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
        return -1;
    }
    zyre_set_port(self->node, port);
    peer_errno = PEER_SUCCESS;
    return 0;
}

int peer_set_evasive_timeout(peer_t *self, unsigned int interval_ms)
{
    assert(self);
    assert(self->node);
    if (interval_ms > PEER_INTERVAL_MS_MAX) //
    {
        peer_errno = -PEER_INTERVAL_TOO_LARGE;
        return -1;
    }
    zyre_set_evasive_timeout(self->node, interval_ms);
    peer_errno = PEER_SUCCESS;
    return 0;
}

int peer_set_silent_timeout(peer_t *self, unsigned int interval_ms)
{
    assert(self);
    assert(self->node);
    if (interval_ms > PEER_INTERVAL_MS_MAX) //
    {
        peer_errno = -PEER_INTERVAL_TOO_LARGE;
        return -1;
    }
    zyre_set_silent_timeout(self->node, interval_ms);
    peer_errno = PEER_SUCCESS;
    return 0;
}

int peer_set_expired_timeout(peer_t *self, unsigned int interval_ms)
{
    assert(self);
    assert(self->node);
    if (interval_ms > PEER_INTERVAL_MS_MAX) //
    {
        peer_errno = -PEER_INTERVAL_TOO_LARGE;
        return -1;
    }
    zyre_set_expired_timeout(self->node, interval_ms);
    peer_errno = PEER_SUCCESS;
    return 0;
}

int peer_set_interval(peer_t *self, size_t interval_ms)
{
    assert(self);
    assert(self->node);
    if (interval_ms > PEER_INTERVAL_MS_MAX) //
    {
        peer_errno = -PEER_INTERVAL_TOO_LARGE;
        return -1;
    }
    zyre_set_interval(self->node, interval_ms);
    peer_errno = PEER_SUCCESS;
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
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, self->group_hash); // somehow group info is not sent when whispering
    if (rc)
    {
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, internal_message_type);
    if (rc)
    {
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, message_type);
    if (rc)
    {
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    if ((data != NULL) && (data_len > 0))
    {
        rc = zmsg_addmem(msg, data, data_len);
        if (rc)
        {
            peer_errno = -PEER_ZMSG_MEM_INSERT_FAILED;
            goto clean_msg_type;
        }
    }

    rc = zyre_whisper(self->node, peer, &msg);
    if (rc)
    {
        peer_errno = -PEER_ZYRE_WHISPER_FAILED;
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

    if (!validate_name(name))
    {
        return -1;
    }

    rc = validate_message_type(message_type);
    if (!rc)
    {
        return -1;
    }

    char *msg_type = strdup(message_type);
    if (!msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        return -1;
    }
    str_to_lower(msg_type);

    if (!data)
    {
        peer_errno = -PEER_MESSAGE_PAYLOAD_NULL;
        return -1;
    }
    if (data_len == 0)
    {
        peer_errno = -PEER_MESSAGE_PAYLOAD_LENGTH_ZERO;
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
        return -1;
    }
    else
    {
        strncpy(last_name, name, PEER_NAME_MAXLEN); // update name
        strncpy(last_peer_name, uuid, 33);                  // update uuid
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

    if (!validate_name(name))
    {
        return -1;
    }

    rc = validate_message_type(message_type);
    if (!rc)
    {
        return -1;
    }

    char *msg_type = strdup(message_type);
    if (!msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        return -1;
    }
    str_to_lower(msg_type);

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
        return -1;
    }
    else
    {
        strncpy(last_name, name, PEER_NAME_MAXLEN); // update name
        strncpy(last_peer_name, uuid, 33);                  // update uuid
    }
commence:
    va_start(argptr, format);
    string = zsys_vprintf(format, argptr);
    va_end(argptr);
    rc = peer_whisper_internal(self, uuid, EXTERNAL_MESSAGE_STR, msg_type, string, strlen(string) + 1);
    if (rc)
    {
        peer_errno = -PEER_ZYRE_WHISPERS_FAILED;
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

    if (!validate_message_type(message_type))
    {
        return -1;
    }

    if (!data)
    {
        peer_errno = -PEER_MESSAGE_PAYLOAD_NULL;
        return -1;
    }
    if (data_len == 0)
    {
        peer_errno = -PEER_MESSAGE_PAYLOAD_LENGTH_ZERO;
        return -1;
    }

    char *msg_type = strdup(message_type);
    if (!msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        return -1;
    }
    str_to_lower(msg_type);

    zmsg_t *msg = zmsg_new();
    if (!msg)
    {
        peer_errno = -PEER_ZMSG_NEW_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, EXTERNAL_MESSAGE_STR);
    if (rc)
    {
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, msg_type);
    if (rc)
    {
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addmem(msg, data, data_len);
    if (rc)
    {
        peer_errno = -PEER_ZMSG_MEM_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zyre_shout(self->node, self->group_hash, &msg);
    if (rc)
    {
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
        return -1;
    }

    if (!validate_message_type(message_type))
    {
        return -1;
    }

    char *msg_type = strdup(message_type);
    if (!msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        return -1;
    }
    str_to_lower(msg_type);

    zmsg_t *msg = zmsg_new();
    if (!msg)
    {
        peer_errno = -PEER_ZMSG_NEW_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, "");
    if (rc)
    {
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, msg_type);
    if (rc)
    {
        peer_errno = -PEER_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    va_start(argptr, format);
    string = zsys_vprintf(format, argptr);
    va_end(argptr);

    rc = peer_shout(self, msg_type, string, strlen(string) + 1);
    if (rc)
    {
        peer_errno = -PEER_ZYRE_SHOUTS_FAILED;
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
        uuid = "";
    }
    else
    {
        strncpy(last_name, name, PEER_NAME_MAXLEN); // update name
        strncpy(last_peer_name, uuid, 33);                  // update uuid
    }
commence:
    ret = zyre_peer_address(self->node, uuid);
    if (streq(ret, ""))
    {
        peer_errno = -PEER_ZYRE_PEER_ADDRESS_NOT_FOUND;
    }
    else
    {
        peer_errno = PEER_SUCCESS;
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
        uuid = "";
        _name = strdup(name);
    }
    else
    {
        str_to_lower(_name);
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
        uuid = "";
    }
    else
    {
        strncpy(last_name, name, PEER_NAME_MAXLEN); // update name
        strncpy(last_peer_name, uuid, 33);                  // update uuid
    }
commence:
    ret = zyre_peer_header_value(self->node, uuid, _name);
    if (!ret)
    {
        peer_errno = -PEER_ZYRE_PEER_HEADER_VALUE_FAILED;
    }
    else
    {
        peer_errno = PEER_SUCCESS;
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

int peer_start(peer_t *self)
{
    assert(self);
    assert(self->node);
    int rc = 0;
    self->receiver = zactor_new(receiver_actor, self);
    if (!self->callback_driver)
    {
        peer_errno = -PEER_RECEIVER_FAILED;
        goto errored;
    }
    if (zsock_wait(self->receiver))
    {
        peer_errno = -PEER_RECEIVER_FAILED;
        goto errored_destroy;
    }
    zsock_t *receiver_sock = zactor_sock(self->receiver);
    zsock_set_rcvtimeo(receiver_sock, 1000); // wait 100 ms
    int status = -PEER_MAX_ERROR;
    if (!zsock_recv(receiver_sock, "i", &status))
    {
        if (status == -PEER_EXISTS)
        {
            zsys_error("Peer name %s already exists, exiting...", self->name);
            rc = -PEER_EXISTS;
            goto errored_destroy;
        }
    }
    zsock_set_rcvtimeo(receiver_sock, -1); // wait infinite
    peer_errno = PEER_SUCCESS;
    return rc;
errored_destroy:
    zactor_destroy(&self->receiver);
errored:
    return rc;
}

void peer_stop(peer_t *self)
{
    assert(self);
    assert(self->node);

    zsock_send(self->receiver, "s", "$TERM");
    zsock_wait(self->receiver);
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
    str_to_lower(_name);

    char *_msg_type = strdup(message_type);
    if (!_msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        goto cleanup_name;
    }
    str_to_lower(_msg_type);
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
    str_to_lower(_name);

    char *_msg_type = strdup(message_type);
    if (!_msg_type)
    {
        peer_errno = -PEER_STRDUP_FAILED;
        goto cleanup_name;
    }
    str_to_lower(_msg_type);

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
        str_to_lower(_name);
    }
    else
    {
        _name = self->name;
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
        str_to_lower(_name);
    }
    else
    {
        _name = self->name;
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
        str_to_lower(_name);
    }
    else
    {
        _name = self->name;
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
        str_to_lower(_name);
    }
    else
    {
        _name = self->name;
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

static void __peernet_on_connect_demo(peer_t *self, const char *message_type, const char *peer, void *local, void *remote)
{
    printf("\n\nIn connect callback of %s: %s connected\n\n", peer_name(self), peer);
}

static void __peernet_on_exit_demo(peer_t *self, const char *message_type, const char *peer, void *local, void *remote)
{
    printf("\n\nIn disconnect callback of %s: %s disconnected\n\n", peer_name(self), peer);
}

static void __peernet_on_message_demo(peer_t *self, const char *message_type, const char *peer, void *local, void *remote)
{
    char *msg = (char *)remote;
    printf("\n\nIn message callback of %s (type %s): %s says %s\n\n", peer_name(self), message_type, peer, msg);
}

void peer_test(bool verbose)
{
    peer_t *peer_a = peer_new("peer_a", NULL, true);
    peer_t *peer_b = peer_new("peer_b", NULL, true);
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
    assert(!peer_start(peer_a));
    printf("Peer A started\n");
    zclock_sleep(100);
    assert(!peer_start(peer_b));
    printf("Peer B started\n");
    zclock_sleep(1000);
    assert(!peer_whispers(peer_b, peer_name(peer_a), "CHAT", "Hello, %s! I am %s, nice to meet you!", peer_name(peer_a), peer_name(peer_b)));
    zclock_sleep(2000);
    peer_destroy(&peer_a);
    zclock_sleep(1000);
    peer_destroy(&peer_b);
}
// ------------------ END CLASS FUNCTIONS -------------------- //