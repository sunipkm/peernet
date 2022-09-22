# PeerNet: A cross-platform local-network P2P library
PeerNet is a wrapper around the [ZeroMQ Zyre](https://github.com/zeromq/zyre) library,
with a callback based design that makes application building easy. PeerNet is written
in C, just like Zyre and [CZMQ](https://github.com/zeromq/czmq) which PeerNet derives
from.

In PeerNet, a peer can belong to a unique group, and in that group peers can have
unique names. This allows for message parsing based on which peer it came from,
unlike Zyre which concerns more with UUIDs which are generated for peers randomly
at start.

## Ownership and License
PeerNet is developed by Sunip K. Mukherjee. This project uses the MPL v2 license, see LICENSE.
Contributions/ideas are welcome.

## Pre-requisites
This version of PeerNet uses mostly Zyre stable API, with the exception of the
`zyre_set_zcert` draft method from Zyre version 2.0.1. PeerNet will continue to be
compatible with Zyre untill this method changes, at which point PeerNet will require
an update.
The exact versions PeerNet was tested against are listed:
    - Zyre 2.0.1
    - CZMQ 4.2.1
    - ZeroMQ 4.3.4
    - libSodium 1.0.18_1

Additionally, PeerNet requires `cmake` or `autoconf`, `automake` and `libtool` for the build system to work. `pkg-config`, `pcre (libpcre3-dev)` are required for building, alongside Zyre and its pre-requisites.

## Build Process
CMake is the preferred build tool, as it builds the `chat` example and documentations
with ease. To build with CMake, within `peernet` directory, execute:

```
    $ mkdir build && cd build && cmake ..
    $ make
    $ make test
    $ sudo make install
```

This will build the project and execute the self-test program.

Alternatively, in the `peernet` directory, execute:
```
    $ ./autogen.sh
    $ ./configure --prefix="/path/to/library"
    $ make
    $ make install
```

Check out `examples/chat/chat.c` to understand basic usage. The library is also extensively
documented, and a doxygen documentation is generated using the `cmake` build system.

## The 'Chat' example
If built using the `cmake` build system, a `chat.exe` executable is generated in `examples/chat`. To run the program, open a terminal window in the `peernet` directory and run:
```
    $ cd examples/chat
    $ ./chat.exe peer_name
```

In order to properly test the program, open another terminal in the `peernet` directory and repeat the steps above. Using the same `peer_name` as the first instance will cause the
second instance to crash. Multiple such instance can be launched in multiple terminal
windows, and writing anything in one such terminal, and pressing enter will cause the
instance to send the message to all other instances.

The example starts operation by initializing the peer, and starting it:
```c
    peer_t *peer = peer_new("peer_name", NULL, "password", true); // creates a peer named "peer_name" in the default group with password "password" and encryption enabled.
```
At this point, a pre-defined callback function is registered in order to capture any peer that has connected.
```c
    peer_on_connect(peer, NULL, &on_connect_callback, NULL); // registers on_connect_callback as a callback for any peer that connects. The callback does not use any local data.
```

The `on_connect_callback()` function has the following form:
```c
    void on_connect_callback(peer_t *self, const char *message_type, const char *remote_name, void *local_args, void *remote_args)
    {
        peer_on_message(self, remote_name, "CHAT", &on_message_callback, NULL);
    }
```
Essentially, the `on_connect` callback that was registered, registers a callback function that is executed when any peer sends a message, of type "CHAT", to this peer. The `on_message` callback absolutely requires a peer name in order to avoid message spamming.

The `on_message_callback()` function has the following form:
```c
    void on_connect_callback(peer_t *self, const char *message_type, const char *remote_name, void *local_args, void *remote_args)
    {
        printf("%s> %s\n", remote_name, (char *) remote_args);
    }
```

The callback will be executed only for a message of type "CHAT". Since instances of `chat.exe` are talking amongst one another, the message format sanity is guaranteed.

At this point, an instance of the peer can be started:
```c
    peer_start(peer);
```
CZMQ provides a nice variable that can is set when Ctrl + C is pressed (SIGINT is raised),
called `zsys_interrupted`. A `while` loop can be run on this variable after starting the
peer to monitor input from `stdin`, and `shout` the message to all available `chat.exe` clients:
```c
    while (!zsys_interrupted) // run while SIGINT is not raised
    {
        char message[1024];
        if (!fgets (message, 1024, stdin)) // if this returns -1, program was interrupted
            break;
        message[strlen (message) - 1] = 0; // Drop the trailing linefeed
        assert(!peer_shouts(peer, "CHAT", "%s", message));
    }
```
A peer can be stopped after getting out of the `while` loop by either calling `peer_stop`, or by calling `peer_destroy` which will also free all the resources associated with that instance of peer:
```c
    peer_destroy(&peer); // destroy peer
    return 0;
```

All in all, with 36 lines of code, a terminal chat client is implemented.

## Possible Security Concern
Compared to the first version of the API where any Zyre client could snoop at our secret group name and guessed
how to join the local network, an extra password authentication layer has been added. However, this layer is only
marginally more effective as nothing prevents an adversary from snooping the group name (that is probably not
changing very often), and starting a peer in that group (which will become the first peer connected, hence the
primary arbiter of the group as it will allow/disallow the next peer to enter the group.) This is definitely going
to prevent intrusion into an existing network, but does not prevent access after an attempt at a network restart.
More work is needed in this front, and ideas are very much welcome.

