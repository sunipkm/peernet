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

#include "peernet.h"
#include "peernet_private.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "utilities/md5sum.h"

static const char *peernet_error_str[PEERNET_MAX_ERROR] = {
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
};

#ifdef __WINDOWS__
__declspec(thread) int peernet_errno = PEERNET_SUCCESS;
#else
__thread int peernet_errno = PEERNET_SUCCESS;
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
    peernet_callback_t self_on_connect_cb;
    void *self_on_connect_cb_args;
    peernet_callback_t self_on_exit_cb;
    void *self_on_exit_cb_args;
    zlist_t *message_types_registerd;
    zhash_t *available_peers;    // zhash of peers, keyed by name
    zhash_t *available_uuids;    // zhash of peers, keyed by uuid
    zhash_t *on_connect_cbs;     // zhash of callback fcns, keyed by name
    zhash_t *on_connect_cb_args; // zhash of callback fcn args, keyed by name
    zhash_t *on_exit_cbs;        // zhash of callback fcns, keyed by name
    zhash_t *on_exit_cb_args;    // zhash of callback fcns, keyed by name
    zhash_t *on_message_cbs;     // callback functions keyed by message type
    zhash_t *on_message_cb_args; // callback function args keyed by message type
};

struct callback_t
{
    peernet_callback_t fcn;
    char *message_type;
    char *peer;
    void *local_data;
    void *remote_data;
};

// ------------------ HELPER FUNCTIONS -------------------- //

static inline void destroy_ptr(void **ptr)
{
    if (*ptr)
    {
        free(*ptr);
        *ptr = NULL;
    }
}

const char *peernet_strerror(int error_code)
{
    static const char *invalid_msg = "Invalid error code.";
    if (error_code > 0)
    {
        return invalid_msg;
    }
    error_code = -error_code;
    if (error_code > PEERNET_MAX_ERROR)
    {
        return invalid_msg;
    }
    return peernet_error_str[error_code];
}

static inline bool valid_name_str(const char *name)
{
    bool name_valid = true;
    char *s = name;
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

    destroy_ptr(&_name);

    return uuid;
}

static inline int validate_name(const char *name)
{
    if (!name)
    {
        peernet_errno = -PEERNET_NAME_IS_NULL;
        return -1;
    }
    if (strlen(name) > PEERNET_PEER_NAME_MAXLEN)
    {
        peernet_errno = -PEERNET_PEER_NAME_LENGTH_INVALID;
        return -1;
    }
    if (strlen(name) < PEERNET_PEER_NAME_MINLEN)
    {
        peernet_errno = -PEERNET_PEER_NAME_LENGTH_INVALID;
        return -1;
    }
    if (!valid_name_str(name))
    {
        peernet_errno = -PEERNET_PEER_NAME_INVALID_CHARS;
        return -1;
    }
    peernet_errno = PEERNET_SUCCESS;
    return 0;
}

static inline int validate_group(const char *group)
{
    if (!group)
    {
        peernet_errno = -PEERNET_GROUP_IS_NULL;
        return -1;
    }
    int name_len = strlen(group);
    if (name_len > PEERNET_PEER_GROUP_MAXLEN)
    {
        peernet_errno = -PEERNET_PEER_GROUP_LENGTH_INVALID;
        return -1;
    }
    if (name_len < PEERNET_PEER_GROUP_MINLEN)
    {
        peernet_errno = -PEERNET_PEER_GROUP_LENGTH_INVALID;
    }
    bool name_valid = valid_name_str(group);
    if (!name_valid)
    {
        peernet_errno = -PEERNET_PEER_GROUP_INVALID_CHARS;
        return -1;
    }
    peernet_errno = PEERNET_SUCCESS;
    return 0;
}

static inline int validate_message_type(const char *message_type)
{
    if (!message_type)
    {
        peernet_errno = -PEERNET_MESSAGETYPE_IS_NULL;
        return -1;
    }
    if (strlen(message_type) > PEERNET_PEER_MESSAGETYPE_MAXLEN)
    {
        peernet_errno = -PEERNET_MESSAGETYPE_LENGTH_INVALID;
        return -1;
    }
    if (strlen(message_type) < PEERNET_PEER_MESSAGETYPE_MINLEN)
    {
        peernet_errno = -PEERNET_MESSAGETYPE_LENGTH_INVALID;
        return -1;
    }
    if (!valid_name_str(message_type))
    {
        peernet_errno = -PEERNET_MESSAGETYPE_INVALID_CHARS;
        return -1;
    }
    peernet_errno = PEERNET_SUCCESS;
    return -1;
}
// ---------------- END HELPER FUNCTIONS -------------------- //

static void callback_actor(zsock_t *pipe, void *arg)
{
    assert(pipe);
    assert(arg);
    peer_t *self = (peer_t *)arg;
    bool terminated = false;
    int executed = 0;
    zpoller_t *poller = zpoller_new(pipe, NULL);
    if (!poller)
    {
        peernet_errno = -PEERNET_COULD_NOT_CREATE_ZPOLLER;
        goto errored;
    }
    while (!terminated)
    {
        void *which = zpoller_wait(poller, -1);
        if (which == pipe) // the only option
        {
            zmsg_t *msg = zmsg_recv(which);
            char *command = zmsg_popstr(which);
            if (streq(command, "$TERM"))
                terminated = true;
            else if (streq(command, "CALLBACK"))
            {
                zframe_t *frame = zmsg_pop(msg);
                if (zframe_size(frame) != sizeof(struct callback_t))
                {
                    zsys_error("Received callback frame size %u, actual size %u.", (unsigned int)zframe_size(frame), (unsigned int)sizeof(struct callback_t));
                }
                else
                {
                    struct callback_t *cb_data = zframe_data(frame);
                    if (cb_data && cb_data->fcn)
                    {
                        if (self->verbose)
                            zsys_info("Executing callback function at %p.", cb_data->fcn);
                        // zsock_send(pipe, "i", executed++);
                        cb_data->fcn(self, cb_data->message_type, cb_data->peer, cb_data->local_data, cb_data->remote_data);
                        // zsock_send(pipe, "i", executed);
                        if (self->verbose)
                            zsys_info("Executed callback function at %p", cb_data->fcn);
                    }
                }
                zframe_destroy(&frame);
            }
            free(command);
            zmsg_destroy(&msg);
        }
    }
    zsock_send(pipe, "i", PEERNET_SUCCESS);
    return;
errored:
    zsock_send(pipe, "i", peernet_errno);
    return;
}

static void receiver_actor(zsock_t *pipe, void *_args) // Forward declaration.
{
    struct _peer_t *self = (peer_t *)_args;
    zyre_t *node = self->node;
    int rc = 0;
    self->callback_driver = zactor_new(callback_actor, &(self->verbose));
    if (!self->callback_driver)
    {
        peernet_errno = -PEERNET_CALLBACK_DRIVER_FAILED;
        goto errored;
    }
    rc = zyre_start(node);
    if (rc)
    {
        peernet_errno = -PEERNET_PEER_NODE_START_FAILED;
        goto errored;
    }
    rc = zyre_join(node, self->group_hash);
    if (rc)
    {
        peernet_errno = -PEERNET_PEER_NODE_GROUP_JOIN_FAILED;
        goto errored;
    }
    rc = zsock_signal(pipe, 0);
    if (rc)
    {
        peernet_errno = -PEERNET_COULD_NOT_SIGNAL_PIPE;
        goto errored;
    }
    zpoller_t *poller = zpoller_new(pipe, zyre_socket(node), NULL);
    if (!poller)
    {
        peernet_errno = -PEERNET_COULD_NOT_CREATE_ZPOLLER;
        goto errored;
    }

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
                terminated = true;
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

            if (streq(event, "WHISPER") && streq(internal_msg, "INTERNAL_MESSAGE")) // check internal messages
            {
                if (streq(message_type, "NAME_CONFLICT_EVICT"))
                {
                    zsock_send(pipe, "i", -PEERNET_PEER_EXISTS);
                    terminated = true;
                }
                else if (streq(message_type, "NAME_OKAY"))
                {
                    zsock_send(pipe, "i", PEERNET_SUCCESS);
                }
            }

            else if (streq(event, "ENTER")) // a peer has entered
            {
                bool in_our_group = (strcmp(group, self->group_hash) == 0); // check if peer is in our group by comparing the group name sent by the peer against our group hash
                if (self->verbose)
                {
                    zsys_info("%s[%s] has joined [%s]\n", name, uuid, in_our_group == true ? self->group : group);
                }
                if (in_our_group) // in our group
                {
                    if (!zhash_insert(self->available_peers, name, uuid)) // peer name not already in available peers list
                    {
                        zhash_insert(self->available_uuids, uuid, name); // update inverse list as well
                        if (self->verbose)
                        {
                            zsys_info("Peer name OK: %s, sending name induction message to %s!", name, uuid);
                        }
                        rc = peernet_whisper_internal(self, uuid, "INTERNAL_MESSAGE", "NAME_OKAY", NULL, 0);
                        if (rc)
                        {
                            zsys_error("Peer name OK: %s, could not send message to %s!", name, uuid);
                        }
                    }
                    else
                    {
                        if (self->verbose)
                        {
                            zsys_info("Peer name conflict: %s, sending name conflict message to %s!", name, uuid);
                        }
                        rc = peernet_whisper_internal(self, uuid, "INTERNAL_MESSAGE", "NAME_CONFLICT_EVICT", NULL, 0);
                        if (rc)
                        {
                            zsys_error("Peer name conflict: %s, could not send message to %s!", name, uuid);
                        }
                    }
                }
            }

            else if (streq(event, "EXIT"))
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
                        char *rname = zhash_lookup(self->available_peers, uuid);
                        zhash_delete(self->available_peers, rname);
                        zhash_delete(self->available_uuids, uuid);
                        if (self->verbose)
                        {
                            zsys_info("Peer name %s [%s] leaving.", name, uuid);
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

            else if (streq(event, "WHISPER") && streq(internal_msg, "")) // user message
            {
            }

            else if (streq(event, "SHOUT") && streq(internal_msg, "")) // user shout
            {
            }

            free(event);
            free(uuid);
            free(name);
            free(group);
            free(internal_msg);
            free(message_type);
            zmsg_destroy(&msg);
        }
    }
    zactor_destroy(&(self->callback_driver)); // terminate the callback driver
    zsock_send(pipe, "i", PEERNET_SUCCESS);
errored:
    self->exited = true;
    zsock_send(pipe, "i", peernet_errno);
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
    if (rc)
    {
        return NULL;
    }
    // 2. Check group name
    if (group) // non NULL
    {
        if (validate_group(group))
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
        peernet_errno = -PEERNET_PEER_GROUP_HASH_FAILED;
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
        peernet_errno = -PEERNET_PEER_NODE_CREATE_FAILED;
        goto cleanup_all;
    }
    if (encryption)
    {
        zyre_set_zcert(self->node, cert);
        zcert_destroy(cert);
    }
    self->name = zyre_name(self->node);
    self->group = _group;
    self->group_hash = strndup(_group_hash, 33);
    self->exited = false;
    destroy_ptr(&_name);
    destroy_ptr(&group_hash);

    self->available_peers = zhash_new();
    assert(self->available_peers);
    if (zhash_insert(self->available_peers, zyre_name(self->node), zyre_uuid(self->node)))
    {
        peernet_errno = -PEERNET_PEER_SELF_INSERTION_FAILED;
        goto cleanup_all;
    }
    self->available_uuids = zhash_new();
    assert(self->available_uuids);
    if (zhash_insert(self->available_peers, zyre_uuid(self->node), zyre_name(self->node)))
    {
        peernet_errno = -PEERNET_PEER_SELF_INSERTION_FAILED;
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
    self->message_types_registerd = zlist_new();
    assert(self->message_types_registerd);
    self->on_message_cbs = zhash_new();
    assert(self->on_message_cbs);
    self->on_message_cb_args = zhash_new();
    assert(self->on_message_cb_args);

    peernet_errno = PEERNET_SUCCESS;
    return self;
cleanup_all:
    destroy_ptr(&self);
cleanup_group:
    destroy_ptr(&group_hash);
    destroy_ptr(&_group);
cleanup_name:
    destroy_ptr(&_name);
ret_error:
    zcert_destroy(&cert);
    return self;
}

void peer_destroy(peer_t **self_p)
{
    assert(*self_p);
    peer_t *self = *self_p;
    peer_stop(self);
    destroy_ptr(self_p);
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
        peernet_errno = -PEERNET_PORT_RANGE_INVALID;
        return -1;
    }
    zyre_set_port(self->node, port);
    peernet_errno = PEERNET_SUCCESS;
    return 0;
}

int peer_set_evasive_timeout(peer_t *self, unsigned int interval_ms)
{
    assert(self);
    assert(self->node);
    if (interval_ms > PEERNET_INTERVAL_MS_MAX) //
    {
        peernet_errno = -PEERNET_INTERVAL_TOO_LARGE;
        return -1;
    }
    zyre_set_evasive_timeout(self->node, interval_ms);
    peernet_errno = PEERNET_SUCCESS;
    return 0;
}

int peer_set_silent_timeout(peer_t *self, unsigned int interval_ms)
{
    assert(self);
    assert(self->node);
    if (interval_ms > PEERNET_INTERVAL_MS_MAX) //
    {
        peernet_errno = -PEERNET_INTERVAL_TOO_LARGE;
        return -1;
    }
    zyre_set_silent_timeout(self->node, interval_ms);
    peernet_errno = PEERNET_SUCCESS;
    return 0;
}

int peer_set_expired_timeout(peer_t *self, unsigned int interval_ms)
{
    assert(self);
    assert(self->node);
    if (interval_ms > PEERNET_INTERVAL_MS_MAX) //
    {
        peernet_errno = -PEERNET_INTERVAL_TOO_LARGE;
        return -1;
    }
    zyre_set_expired_timeout(self->node, interval_ms);
    peernet_errno = PEERNET_SUCCESS;
    return 0;
}

int peer_set_interval(peer_t *self, size_t interval_ms)
{
    assert(self);
    assert(self->node);
    if (interval_ms > PEERNET_INTERVAL_MS_MAX) //
    {
        peernet_errno = -PEERNET_INTERVAL_TOO_LARGE;
        return -1;
    }
    zyre_set_interval(self->node, interval_ms);
    peernet_errno = PEERNET_SUCCESS;
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

    rc = validate_name(peer);
    if (rc)
    {
        return -1;
    }

    rc = validate_message_type(message_type);
    if (rc)
    {
        return -1;
    }

    if (!data)
    {
        peernet_errno = -PEERNET_MESSAGE_PAYLOAD_NULL;
        return -1;
    }
    if (data_len == 0)
    {
        peernet_errno = -PEERNET_MESSAGE_PAYLOAD_LENGTH_ZERO;
        return -1;
    }

    char *msg_type = strdup(message_type);
    if (!msg_type)
    {
        peernet_errno = -PEERNET_STRDUP_FAILED;
        return -1;
    }
    str_to_lower(msg_type);

    zmsg_t *msg = zmsg_new();
    if (!msg)
    {
        peernet_errno = -PEERNET_ZMSG_NEW_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, internal_message_type);
    if (rc)
    {
        peernet_errno = -PEERNET_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, msg_type);
    if (rc)
    {
        peernet_errno = -PEERNET_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    if ((data != NULL) && (data_len > 0))
    {
        rc = zmsg_addmem(msg, data, data_len);
        if (rc)
        {
            peernet_errno = -PEERNET_ZMSG_MEM_INSERT_FAILED;
            goto clean_msg_type;
        }
    }

    rc = zyre_whisper(self->node, peer, &msg);
    if (rc)
    {
        peernet_errno = -PEERNET_ZYRE_WHISPER_FAILED;
    }
clean_msg_type:
    free(msg_type);
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

    if (validate_name(name))
    {
        return -1;
    }

    if (!data)
    {
        peernet_errno = -PEERNET_MESSAGE_PAYLOAD_NULL;
        return -1;
    }
    if (data_len == 0)
    {
        peernet_errno = -PEERNET_MESSAGE_PAYLOAD_LENGTH_ZERO;
        return -1;
    }

    const char *uuid = NULL;
    if (strncasecmp(last_name, name, PEERNET_PEER_NAME_MAXLEN) == 0) // check name against last name
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
        peernet_errno = -PEERNET_DESTINATION_PEER_NOT_FOUND;
        return -1;
    }
    else
    {
        strncpy(last_name, name, PEERNET_PEER_NAME_MAXLEN); // update name
        strncpy(last_peer_name, uuid, 33);                  // update uuid
    }
commence:
    return peernet_whisper_internal(self, uuid, "", message_type, data, data_len);
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

    assert(self);
    assert(self->node);

    if (!format)
    {
        peernet_errno = -PEERNET_FORMAT_STR_IS_NULL;
        return -1;
    }

    if (validate_name(name))
    {
        return -1;
    }

    if (validate_message_type(message_type))
    {
        return -1;
    }

    const char *uuid = NULL;
    if (strncasecmp(last_name, name, PEERNET_PEER_NAME_MAXLEN) == 0) // check name against last name
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
        peernet_errno = -PEERNET_DESTINATION_PEER_NOT_FOUND;
        return -1;
    }
    else
    {
        strncpy(last_name, name, PEERNET_PEER_NAME_MAXLEN); // update name
        strncpy(last_peer_name, uuid, 33);                  // update uuid
    }
commence:
    char *msg_type = strdup(message_type);
    if (!msg_type)
    {
        peernet_errno = -PEERNET_STRDUP_FAILED;
        return -1;
    }
    str_to_lower(msg_type);

    zmsg_t *msg = zmsg_new();
    if (!msg)
    {
        peernet_errno = -PEERNET_ZMSG_NEW_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, "");
    if (rc)
    {
        peernet_errno = -PEERNET_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, msg_type);
    if (rc)
    {
        peernet_errno = -PEERNET_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    va_list argptr;
    va_start(argptr, format);
    char *string = zsys_vprintf(format, argptr);
    va_end(argptr);

    rc = zyre_whispers(self->node, uuid, "%s", string);
    if (rc)
    {
        peernet_errno = -PEERNET_ZYRE_WHISPERS_FAILED;
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

    if (validate_message_type(message_type))
    {
        return -1;
    }

    if (!data)
    {
        peernet_errno = -PEERNET_MESSAGE_PAYLOAD_NULL;
        return -1;
    }
    if (data_len == 0)
    {
        peernet_errno = -PEERNET_MESSAGE_PAYLOAD_LENGTH_ZERO;
        return -1;
    }

    char *msg_type = strdup(message_type);
    if (!msg_type)
    {
        peernet_errno = -PEERNET_STRDUP_FAILED;
        return -1;
    }
    str_to_lower(msg_type);

    zmsg_t *msg = zmsg_new();
    if (!msg)
    {
        peernet_errno = -PEERNET_ZMSG_NEW_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, "");
    if (rc)
    {
        peernet_errno = -PEERNET_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, msg_type);
    if (rc)
    {
        peernet_errno = -PEERNET_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addmem(msg, data, data_len);
    if (rc)
    {
        peernet_errno = -PEERNET_ZMSG_MEM_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zyre_shout(self->node, self->group_hash, &msg);
    if (rc)
    {
        peernet_errno = -PEERNET_ZYRE_SHOUT_FAILED;
    }
clean_msg_type:
    free(msg_type);
    return rc;
}

int peer_shouts(peer_t *self, const char *message_type, const char *format, ...)
{
    int rc = -1;

    assert(self);
    assert(self->node);

    if (!format)
    {
        peernet_errno = -PEERNET_FORMAT_STR_IS_NULL;
        return -1;
    }

    if (!validate_message_type(message_type))
    {
        return -1;
    }

    char *msg_type = strdup(message_type);
    if (!msg_type)
    {
        peernet_errno = -PEERNET_STRDUP_FAILED;
        return -1;
    }
    str_to_lower(msg_type);

    zmsg_t *msg = zmsg_new();
    if (!msg)
    {
        peernet_errno = -PEERNET_ZMSG_NEW_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, "");
    if (rc)
    {
        peernet_errno = -PEERNET_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    rc = zmsg_addstr(msg, msg_type);
    if (rc)
    {
        peernet_errno = -PEERNET_ZMSG_STR_INSERT_FAILED;
        goto clean_msg_type;
    }

    va_list argptr;
    va_start(argptr, format);
    char *string = zsys_vprintf(format, argptr);
    va_end(argptr);

    rc = zyre_shouts(self->node, self->group_hash, "%s", string);
    if (rc)
    {
        peernet_errno = -PEERNET_ZYRE_SHOUTS_FAILED;
    }
    free(string);
clean_msg_type:
    free(msg_type);
    return rc;
}

zhash_t *peernet_peers(peer_t *self)
{
    assert(self);
    assert(self->node);
    return self->available_peers;
}

char *peernet_peer_address(peer_t *self, const char *name)
{
    static char last_name[16] = {
        0x0,
    };
    static char last_peer_name[33] = {
        0x0,
    };
    const char *uuid = NULL;

    assert(self);
    assert(self->node);

    if (validate_name(name))
    {
        uuid = "";
    }

    if (strncasecmp(last_name, name, PEERNET_PEER_NAME_MAXLEN) == 0) // check name against last name
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
        peernet_errno = -PEERNET_DESTINATION_PEER_NOT_FOUND;
        uuid = "";
    }
    else
    {
        strncpy(last_name, name, PEERNET_PEER_NAME_MAXLEN); // update name
        strncpy(last_peer_name, uuid, 33);                  // update uuid
    }
commence:
    char *ret = zyre_peer_address(self->node, uuid);
    if (streq(ret, ""))
    {
        peernet_errno = -PEERNET_ZYRE_PEER_ADDRESS_NOT_FOUND;
    }
    else
    {
        peernet_errno = PEERNET_SUCCESS;
    }
    return ret;
}

char *peernet_peer_header_value(peer_t *self, const char *name)
{
    static char last_name[16] = {
        0x0,
    };
    static char last_peer_name[33] = {
        0x0,
    };
    const char *uuid = NULL;

    assert(self);
    assert(self->node);

    if (!validate_name(name))
        uuid = "";

    char *_name = strdup(name);
    if (!_name)
    {
        peernet_errno = -PEERNET_STRDUP_FAILED;
        uuid = "";
        _name = name;
    }
    else
    {
        str_to_lower(_name);
    }

    if (strncasecmp(last_name, name, PEERNET_PEER_NAME_MAXLEN) == 0) // check name against last name
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
        peernet_errno = -PEERNET_DESTINATION_PEER_NOT_FOUND;
        uuid = "";
    }
    else
    {
        strncpy(last_name, name, PEERNET_PEER_NAME_MAXLEN); // update name
        strncpy(last_peer_name, uuid, 33);                  // update uuid
    }
commence:
    char *ret = zyre_peer_header_value(self->node, uuid, _name);
    if (!ret)
    {
        peernet_errno = -PEERNET_ZYRE_PEER_HEADER_VALUE_FAILED;
    }
    else
    {
        peernet_errno = PEERNET_SUCCESS;
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
    printf("Message types: ");
    char *name = zlist_first(self->message_types_registerd);
    while (name)
    {
        printf("%s, ", name);
        name = zlist_next(self->message_types_registerd);
    }
    printf("\n");
    printf("-- END --\n\n");
}

uint64_t peernet_version()
{
    return PEERNET_VERSION;
}

zyre_t *peer_get_backend(peer_t *self)
{
    assert(self);
    return self->node;
}

int peer_start(peer_t *self)
{
}

void peer_stop(peer_t *self)
{
}

int peer_on_message(peer_t *self, const char *message_type, const char *name, peernet_callback_t callback, void *local_args)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->message_types_registerd);
    assert(self->on_message_cb_args);
    assert(self->on_message_cbs);

    char hash_name[PEERNET_PEER_NAME_MAXLEN + PEERNET_PEER_MESSAGETYPE_MAXLEN + 2] = {
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
        peernet_errno = -PEERNET_STRDUP_FAILED;
        return -1;
    }
    str_to_lower(_name);

    char *_msg_type = strdup(message_type);
    if (!_msg_type)
    {
        peernet_errno = -PEERNET_STRDUP_FAILED;
        goto cleanup_name;
    }
    str_to_lower(_msg_type);

    int len = snprintf(hash_name, sizeof(hash_name), "%s.%s", _msg_type, _name);
    if (len != strlen(_msg_type) + strlen(_name) + 1)
    {
        peernet_errno = -PEERNET_STRCONCAT_FAILED;
        goto cleanup_msg_type;
    }

    zhash_delete(self->on_message_cbs, hash_name);
    zhash_delete(self->on_message_cb_args, hash_name);

    if ((rc = zhash_insert(self->on_message_cbs, _name, callback)))
    {
        peernet_errno = -PEERNET_CALLBACK_INSERTION_FAILED;
        goto cleanup_msg_type;
    }
    if ((rc = zhash_insert(self->on_message_cb_args, _name, local_args)))
    {
        zhash_delete(self->on_message_cbs, _name);
        peernet_errno = -PEERNET_CALLBACK_LOCALARG_INSERTION_FAILED;
        goto cleanup_msg_type;
    }
    peernet_errno = PEERNET_SUCCESS;
cleanup_msg_type:
    destroy_ptr(&_msg_type);
cleanup_name:
    destroy_ptr(&_name);
    return rc;
}

int peer_disable_on_message(peer_t *self, const char *message_type, const char *name)
{
    int rc = -1;

    assert(self);
    assert(self->node);
    assert(self->message_types_registerd);
    assert(self->on_message_cb_args);
    assert(self->on_message_cbs);

    char hash_name[PEERNET_PEER_NAME_MAXLEN + PEERNET_PEER_MESSAGETYPE_MAXLEN + 2] = {
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
        peernet_errno = -PEERNET_STRDUP_FAILED;
        return -1;
    }
    str_to_lower(_name);

    char *_msg_type = strdup(message_type);
    if (!_msg_type)
    {
        peernet_errno = -PEERNET_STRDUP_FAILED;
        goto cleanup_name;
    }
    str_to_lower(_msg_type);

    int len = snprintf(hash_name, sizeof(hash_name), "%s.%s", _msg_type, _name);
    if (len != strlen(_msg_type) + strlen(_name) + 1) // should this be an assert?
    {
        peernet_errno = -PEERNET_STRCONCAT_FAILED;
        goto cleanup_msg_type;
    }

    // 1. Check if message type at all registered
    if (!zlist_exists(zhash_keys(self->on_connect_cbs), hash_name))
    {
        peernet_errno = -PEERNET_MESSAGE_TYPE_NOT_REGISTERED;
        goto cleanup_msg_type;
    }

    zhash_delete(self->on_connect_cbs, hash_name);
    zhash_delete(self->on_connect_cb_args, hash_name);
    peernet_errno = PEERNET_SUCCESS;
    rc = 0;
cleanup_msg_type:
    destroy_ptr(&_msg_type);
cleanup_name:
    destroy_ptr(&_name);
    return rc;
}

int peer_on_connect(peer_t *self, const char *peer, peernet_callback_t _Nullable callback, void *local_args)
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
            peernet_errno = -PEERNET_STRDUP_FAILED;
            return -1;
        }
        str_to_lower(_name);
    }
    else
    {
        _name = self->name;
    }
    assert(_name);

    if (zlist_exists(zhash_keys(self->on_connect_cbs), _name)) // already exists
    {
        zhash_delete(self->on_connect_cbs, _name);
        zhash_delete(self->on_connect_cb_args, _name);
    }

    if ((rc = zhash_insert(self->on_connect_cbs, _name, callback)))
    {
        peernet_errno = -PEERNET_CALLBACK_INSERTION_FAILED;
        goto cleanup_name;
    }

    if ((rc = zhash_insert(self->on_connect_cb_args, _name, local_args)))
    {
        peernet_errno = -PEERNET_CALLBACK_LOCALARG_INSERTION_FAILED;
        zhash_delete(self->on_connect_cbs, _name);
        goto cleanup_name;
    }
    peernet_errno = PEERNET_SUCCESS;
cleanup_name:
    destroy_ptr(&_name);
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
            peernet_errno = -PEERNET_STRDUP_FAILED;
            return -1;
        }
        str_to_lower(_name);
    }
    else
    {
        _name = self->name;
    }
    assert(_name);

    if (zlist_exists(zhash_keys(self->on_connect_cbs), _name)) // already exists
    {
        zhash_delete(self->on_connect_cbs, _name);
        zhash_delete(self->on_connect_cb_args, _name);
        peernet_errno = PEERNET_SUCCESS;
        rc = 0;
    }
    else
    {
        peernet_errno = -PEERNET_CALLBACK_DOES_NOT_EXIST;
        rc = -1;
    }
cleanup_name:
    destroy_ptr(&_name);
    return rc;
}

int peer_on_disconnect(peer_t *self, const char *peer, peernet_callback_t _Nullable callback, void *local_args)
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
            peernet_errno = -PEERNET_STRDUP_FAILED;
            return -1;
        }
        str_to_lower(_name);
    }
    else
    {
        _name = self->name;
    }
    assert(_name);

    if (zlist_exists(zhash_keys(self->on_exit_cbs), _name)) // already exists
    {
        zhash_delete(self->on_exit_cbs, _name);
        zhash_delete(self->on_exit_cb_args, _name);
    }

    if ((rc = zhash_insert(self->on_exit_cbs, _name, callback)))
    {
        peernet_errno = -PEERNET_CALLBACK_INSERTION_FAILED;
        goto cleanup_name;
    }

    if ((rc = zhash_insert(self->on_exit_cb_args, _name, local_args)))
    {
        peernet_errno = -PEERNET_CALLBACK_LOCALARG_INSERTION_FAILED;
        zhash_delete(self->on_exit_cbs, _name);
        goto cleanup_name;
    }
    peernet_errno = PEERNET_SUCCESS;
cleanup_name:
    destroy_ptr(&_name);
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
            peernet_errno = -PEERNET_STRDUP_FAILED;
            return -1;
        }
        str_to_lower(_name);
    }
    else
    {
        _name = self->name;
    }
    assert(_name);

    if (zlist_exists(zhash_keys(self->on_exit_cbs), _name)) // already exists
    {
        zhash_delete(self->on_exit_cbs, _name);
        zhash_delete(self->on_exit_cb_args, _name);
        peernet_errno = PEERNET_SUCCESS;
        rc = 0;
    }
    else
    {
        peernet_errno = -PEERNET_CALLBACK_DOES_NOT_EXIST;
        rc = -1;
    }
cleanup_name:
    destroy_ptr(&_name);
    return rc;
}
// ------------------ END CLASS FUNCTIONS -------------------- //