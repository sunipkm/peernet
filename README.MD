# PeerNet: A cross-platform local-network P2P library
PeerNet is a wrapper around the [ZeroMQ Zyre](https://github.com/zeromq/zyre) library,
with a callback based design that makes application building easy. PeerNet is written
in C, just like Zyre and [CZMQ](https://github.com/zeromq/czmq) which PeerNet derives
from.

In PeerNet, a peer can belong to a unique group, and in that group peers can have
unique names. This allows for message parsing based on which peer it came from,
unlike Zyre which concerns more with UUIDs which are generated for peers randomly
at start.

A Python wrapper for PeerNet is also available [here](https://github.com/sunipkm/pypeernet).

## Ownership and License
PeerNet is developed by Sunip K. Mukherjee. This project uses the MPL v2 license, see LICENSE.
Contributions/ideas are welcome.

## Pre-requisites
This version of PeerNet uses mostly Zyre stable API, with the exception of the
`zyre_set_zcert` draft method from Zyre version 2.0.1. PeerNet will continue to be
compatible with Zyre untill this method changes, at which point PeerNet will require
an update.
The exact versions PeerNet was tested against are listed:
* Zyre 2.0.1 (`git checkout v2.0.1`)
* CZMQ 4.2.1 (`git checkout v4.2.1`)
* ZeroMQ 4.3.4 (`git checkout v4.3.4`)
* libSodium 1.0.18_1 (`git checkout 1.0.18-RELEASE`)

Additionally, PeerNet requires `cmake` or `autoconf`, `automake` and `libtool` for the build system to work. `pkg-config`, `pcre (libpcre3-dev)` are required for building, alongside Zyre and its pre-requisites.

## Build Process (POSIX)
CMake is the preferred build tool, as it builds the `chat` example and documentations
with ease. To build with CMake, within `peernet` directory, execute:

```
    $ mkdir build && cd build && cmake ..
    $ make
    $ make test
    $ sudo make install
```

This will build the project and execute the self-test program. Specify `-DCMAKE_INSTALL_PREFIX=/path/to/install` to set a custom installation
prefix path (hereafter referred to as prefix path). The default prefix path is `/usr/local`.

Alternatively, in the `peernet` directory, execute:
```
    $ ./autogen.sh
    $ ./configure --prefix="/path/to/library"
    $ make
    $ make install
```

Check out `examples/chat/chat.c` to understand basic usage. The library is also extensively
documented, and a doxygen documentation is generated using the `cmake` build system.

The PeerNet install prefix path defaults to `/usr/local/` if using the `cmake` build system, or `--prefix` is not supplied in `./configure`.
The shared library (`.so` files in Linux and `.dylib` files in macOS) are stored in the `lib` subdirectory under the prefix path.
Make sure the `lib` directory is exported to the `LD_LIBRARY_PATH` variable so that the shared library can be located by other binaries e.g. the
`chat` example, or the [pyPeerNet](https://github.com/sunipkm/pypeernet) Python wrapper.

## Installing on Windows
It is recommended to use the installer associated with a release. The installer automatically adds the binaries to `PATH` for [pyPeerNet](https://github.com/sunipkm/pypeernet).

Alternatively, obtain the binaries from the zip file included with the latest release and extract the contents. Add `\path\to\<x86|x64>\bin` to the `PATH` variable.
Replace `<version>` with the current `PeerNet` version (e.g. `v3.0.0`), and choose the platform (`x86` or `x64`) accordingly for your system.
This step is crucial for [pyPeerNet](https://github.com/sunipkm/pypeernet) to work on Windows.

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
    void on_connect_callback(peer_t *self, const char *message_type, const char *remote_name, void *local_args, void *remote_args, size_t remote_args_len)
    {
        peer_on_message(self, remote_name, "CHAT", &on_message_callback, NULL);
    }
```
Essentially, the `on_connect` callback that was registered, registers a callback function that is executed when any peer sends a message, of type "CHAT", to this peer. The `on_message` callback absolutely requires a peer name in order to avoid message spamming.

The `on_message_callback()` function has the following form:
```c
    void on_connect_callback(peer_t *self, const char *message_type, const char *remote_name, void *local_args, void *remote_args, size_t remote_args_len)
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

## Building on Windows
Building `PeerNet` on Windows systems is not straight forward. Use of the attached binaries is suggested.

To begin with, install Visual Studio Community Edition 2019 with CMake tools.
After the tools are installed, navigate to the `Start Menu`, and find the `Visual Studio 2019` directory sub-menu. Under the sub-menu,
select `<x64|x86> Native Tools Command Prompt` depending on your platform (use the cross-compile command tools as needed). 
This command prompt sets up the build environment with  `cmake`, `cl` (the Visual C++ compiler) etc. Check if you can access 
`git`, `cmake` and `cl` in this command line by typing in the commands one by one. By default, the command line should 
open to `%USERPROFILE%\source\repos` directory. In case it does not, it is recommended that you use the following commands to 
create the aforementioned path and work there.
```cmd
cd %USERPROFILE%
mkdir source
cd source
mkdir repos
cd repos
```
Note: [Git for Windows](https://git-scm.org) may need to be installed separately prior
to opening this command line.

### Building Libsodium
Libsodium is the cryptographic backend that is required. In order to build it:
```cmd
git clone https://github.com/jedisct1/libsodium.git
cd libsodium
git checkout 1.0.18-RELEASE
cd builds\msvc\build
buildall.bat
cd ..\..\..\
```
At this point, the command line should be in the `libsodium` directory. The library files can be found under `bin\<Win32|x64>\<Debug|Release>\<Platform Toolset>\<dynamic|ltcg|static>`.

Here, the `<Platform Toolset>` is the platform toolset you are using: `v100` for `VS2010`, `v140` for `VS2015`, `v141` for `VS2017`, `v142` for `VS2019` etc.

At this point, in comamnd line:
```cmd
start .
cd ..
```
This will open a new `File Explorer` window in the `libsodium` directory, and the required build files for `libsodium` can be accessed. The command line is now in the root
directory containing the `libsodium` directory.

### Building ZeroMQ
```cmd
git clone https://github.com/zeromq/libzmq.git
cd libzmq
git checkout v4.3.4
mkdir build
cd build
cmake .. -DBUILD_STATIC=OFF -DBUILD_SHARED=ON -DZMQ_BUILD_TESTS=ON -DWITH_LIBSODIUM=ON -DCMAKE_INCLUDE_PATH=..\libsodium\src\libsodium\include -DCMAKE_LIBRARY_PATH=..\libsodium\bin\<Win32|x64>\Release\<Platform Toolset>\dynamic -DCMAKE_INSTALL_PREFIX=C:\libzmq
cmake --build . --config Release --target install
cd ..\..\
```
Insert the relevant platform (`Win32/x64`) and toolset (`v142` for `VS2019`) in the `cmake` command.

This will build ZeroMQ with `libsodium`, and install `libzmq` into `C:\libzmq`. You may need to run your shell with administrator privilege in order to write to the system disk, or change
to a directory more suited for your needs. Once `zeromq` is installed, manually copy the `libsodium.dll` file from `libsodium\bin\<Win32|x64>\Release\<Platform Toolset>\dynamic` directory to
`C:\libzmq\bin` directory, and the `libsodium.lib` file from the same directory to `C:\libzmq\lib`. Replace `C:\libzmq` with the `CMAKE_INSTALL_PREFIX` for `zeromq` if it is different.

*Note: `zeromq` builds are toolset specific, and the compiled libraries and DLLs contain the toolset number and version info in the file name. Adequately edit the `zeromq*.lib` file name in `peernet\build_win.bat` file in case a different version and toolset is used. This behavior is not tested.*

### Building CZMQ
```cmd
git clone https://github.com/zeromq/czmq.git
cd czmq
git checkout v4.2.1
mkdir build
cd build
cmake .. -DCZMQ_BUILD_SHARED=ON -DCZMQ_BUILD_STATIC=OFF -DCMAKE_PREFIX_PATH=C:\libzmq -DCMAKE_INSTALL_PREFIX=C:\libzmq
cmake --build . --config Release --target install
```
This will build and install `czmq` into `C:\libzmq`. Replace `C:\libzmq` with the path you used in the previous step.

### Building Zyre
```cmd
git clone https://github.com/zeromq/zyre.git
cd zyre
git checkout v2.0.1
mkdir build
cd build
cmake .. -DZYRE_BUILD_SHARED=ON -DZYRE_BUILD_STATIC=OFF -DCMAKE_PREFIX_PATH=C:\libzmq -DCMAKE_INSTALL_PREFIX=C:\libzmq -DENABLE-DRAFTS=YES 
cmake --build . --config Release --target install
```
This will build and install `zyre` into `C:\libzmq`. Replace `C:\libzmq` with the path you used in the previous step.

### Building PeerNet
```cmd
git clone https://github.com/sunipkm/peernet
cd peernet
git checkout v3.0.0
build_win
``` 
This will create the `Release` directory. The relevant files in this case are `libpeer.dll` and `libpeer.lib`. These files are copied to `C:\libzmq\bin` and `C:\libzmq\lib`, respectively.
The header files (`peer.h`, `peer_library.h`, `peer_private.h`) are copied from `peernet\include` directory to `C:\libzmq\include`. Additionally, the `chat` example (`peerchat.exe`)
is copied to the `C:\libzmq\bin` directory.

Finally, `C:\libzmq\bin` directory should be added to `PATH` for the dynamic libraries to be loaded automatically. At this point, start `peerchat.exe` in `C:\libzmq\lib` from file explorer to
ensure there are no error messages related to missing DLLs. Run `peerchat.exe` in command line (which should be available anywhere if the directory is in path) to test.

## Possible Security Concern
Compared to the first version of the API where any Zyre client could snoop at our secret group name and guessed
how to join the local network, an extra password authentication layer has been added. However, this layer is only
marginally more effective as nothing prevents an adversary from snooping the group name (that is probably not
changing very often), and starting a peer in that group (which will become the first peer connected, hence the
primary arbiter of the group as it will allow/disallow the next peer to enter the group.) This is definitely going
to prevent intrusion into an existing network, but does not prevent access after an attempt at a network restart.
More work is needed in this front, and ideas are very much welcome.

