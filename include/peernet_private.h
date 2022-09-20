#include "peernet.h"
#include "peernet_library.h"

PEERNET_PRIVATE int peer_whisper_internal(peer_t *self, const char *peer, const char *internal_message_type, const char *message_type, void *data, size_t data_len);