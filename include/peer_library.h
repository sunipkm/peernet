/*  =========================================================================
    peer - generated layer of public API

    Copyright (c) Sunip K. Mukherjee.

    This file is part of PeerNet, an open-source framework for proximity-based
    peer-to-peer applications -- See https://github.com/sunipkm/peernet.

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.

################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
    =========================================================================
*/

#ifndef PEER_LIBRARY_H_INCLUDED
#define PEER_LIBRARY_H_INCLUDED

//  Set up environment for the application

//  External dependencies
#include <czmq.h>
#include <zyre.h>

//  PEER version macros for compile-time API detection
#define PEER_VERSION_MAJOR 2
#define PEER_VERSION_MINOR 1
#define PEER_VERSION_PATCH 4

#define PEER_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))
#define PEER_VERSION \
    PEER_MAKE_VERSION(PEER_VERSION_MAJOR, PEER_VERSION_MINOR, PEER_VERSION_PATCH)

#if defined (__WINDOWS__)
#   if defined PEER_STATIC
#       define PEER_EXPORT
#   elif defined PEER_INTERNAL_BUILD
#       if defined DLL_EXPORT
#           define PEER_EXPORT __declspec(dllexport)
#       else
#           define PEER_EXPORT
#       endif
#   elif defined PEER_EXPORTS
#       define PEER_EXPORT __declspec(dllexport)
#   else
#       define PEER_EXPORT __declspec(dllimport)
#   endif
#   define PEER_PRIVATE
#elif defined (__CYGWIN__)
#   define PEER_EXPORT
#   define PEER_PRIVATE
#else
#   if (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
#       define PEER_PRIVATE __attribute__ ((visibility ("hidden")))
#       define PEER_EXPORT __attribute__ ((visibility ("default")))
#   else
#       define PEER_PRIVATE
#       define PEER_EXPORT
#   endif
#endif

//  Project has no stable classes, so we build the draft API
#undef  PEER_BUILD_DRAFT_API
#define PEER_BUILD_DRAFT_API

//  Opaque class structures to allow forward references
//  These classes are stable or legacy and built in all releases
//  Draft classes are by default not built in stable releases
#ifdef PEER_BUILD_DRAFT_API
typedef struct _peer_t peer_t;
#define PEER_T_DEFINED
#endif // PEER_BUILD_DRAFT_API


//  Public classes, each with its own header file

#ifdef PEER_BUILD_DRAFT_API

#ifdef __cplusplus
extern "C" {
#endif

//  Self test for private classes
PEER_EXPORT void
    peer_private_selftest (bool verbose, const char *subtest);

#ifdef __cplusplus
}
#endif
#endif // PEER_BUILD_DRAFT_API

#endif
/*
################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
*/
