#include "peer.h"

const char *random_name()
{
    static char buf[10] = {0x0, };
    for (int i = 0; i < 9; i++)
    {
        buf[i] = 'a' + (rand() % 26);
    }
    return buf;
}

void receive_cb_t(peer_t *peer, const char *message_type, const char *remote_name, void *local_data, void *remote_data, size_t remote_data_len)
{
    // this is the remote data receive
    FILE *fp = (FILE *) local_data;
    assert(fp);
    char *buf = (char *) remote_data;
    assert(buf);
    fprintf(fp, "recv:%s>%s\n", remote_name, buf);
}

void o_receive_cb_t(peer_t *peer, const char *message_type, const char *remote_name, void *local_data, void *remote_data, size_t remote_data_len)
{
    int64_t ts = zclock_usecs();
    peer_whispers(peer, remote_name, "TIME_UPDATE", "%s,%"PRId64, (char *) remote_data, ts);
}

int main(int argc, char *argv[])
{
    if ((argc < 3) || (argc > 4))
    {
        printf("Invocation: ./latency.exe <Number of peers> <runlength> [enable encryption]");
        exit(0);
    }
    int num_peers = atoi(argv[1]);
    int num_loop = atoi(argv[2]);
    num_peers &= 0xfffffffe;
    bool encryption = false;
    if (argc == 4)
        encryption = true;
    assert(num_peers);
    zhash_t *peers = zhash_new();
    // create unique peers
    for (int i = 0; i < num_peers; i++)
    {
        const char *name = random_name();
        peer_t *peer = peer_new(name, NULL, "password", encryption);
        if (!peer)
            printf("Peer error: %s\n", peer_strerror(peer_errno));
        else
            zhash_insert(peers, name, peer);
    }
    // open file
    char buf[100];
    time_t rawtime;
    struct tm *info;
    time( &rawtime );
    info = localtime( &rawtime );
    strftime(buf,80,"%Y%m%d%H%M%S", info);
    FILE *fp = fopen(zsys_sprintf("out_%s.txt", buf), "w");
    assert(fp);
    // associate callback with one peer
    peer_t *peer = zhash_first(peers); // first
    peer_t *o_peer = zhash_next(peers); // second
    for (; o_peer; o_peer = zhash_next(peers))
    {
        assert(!peer_on_message(peer, zhash_cursor(peers), "TIME_UPDATE", receive_cb_t, fp));
        assert(!peer_on_message(o_peer, peer_name(peer), "TIME_UPDATE", o_receive_cb_t, NULL));
    }
    for (peer = zhash_first(peers); peer; peer = zhash_next(peers))
        assert(!peer_start(peer));
    while (num_loop-- && !zsys_interrupted)
    {
        int64_t ts = zclock_usecs();
        peer_shouts(zhash_first(peers), "TIME_UPDATE", "%" PRId64, ts);
        zclock_sleep(1000);
    }
    for (peer = zhash_first(peers); peer; peer = zhash_next(peers))
    {
        peer_destroy(&peer);
    }
    fflush(fp);
    fclose(fp);
    zhash_destroy(&peers);
    return 0;
}