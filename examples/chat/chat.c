/**
 * @file chat.c
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief Chat example using PeerNet.
 * @version 0.1
 * @date 2022-09-20
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "peer.h"

#define CHAT_MESSAGE_TYPE "CHAT"

static void message_received_cb(peer_t *self, const char *message_type, const char *remote_name, void *data_local, void *data_remote, size_t data_remote_len)
{
    if (streq(message_type, CHAT_MESSAGE_TYPE))
        printf("\n%s> %s\n\n", remote_name, (char *)data_remote);
    else
        printf("\n%s> Invalid message request %s", remote_name, message_type);
}

void add_on_connect_cb(peer_t *self, const char *message_type, const char *remote_name, void *data_local, void *data_remote, size_t data_remote_len)
{
    assert(!peer_on_message(self, remote_name, CHAT_MESSAGE_TYPE, &message_received_cb, NULL));
}

int main(int argc, char *argv[])
{
    if ((argc < 2) || (argc > 3))
    {
        puts("syntax: ./chat myname [verbose]");
        exit(0);
    }
    peer_t *peer = peer_new(argv[1], "chat_mongers", "password", true); // create peer
    if (argc == 3)
        peer_set_verbose(peer);
    assert(peer);
    assert(!peer_on_connect(peer, NULL, &add_on_connect_cb, NULL));
    assert(!peer_start(peer)); // start operations
    while (!zsys_interrupted)
    {
        char message[1024];
        if (!fgets(message, 1024, stdin))
            break;
        message[strlen(message) - 1] = 0; // Drop the trailing linefeed
        assert(!peer_shouts(peer, CHAT_MESSAGE_TYPE, "%s", message));
    }
    peer_destroy(&peer);
    return 0;
}