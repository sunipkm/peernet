/**
 * @file peer_library.h
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2022-09-18
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef PEER_LIBRARY_H_INCLUDED
#define PEER_LIBRARY_H_INCLUDED

#define ZYRE_BUILD_DRAFT_API 1
#include <zyre.h>

#define PEER_NAME_MINLEN 4
#define PEER_NAME_MAXLEN 15
#define PEER_GROUP_MINLEN 4
#define PEER_GROUP_MAXLEN 15
#define PEER_MESSAGETYPE_MINLEN 4
#define PEER_MESSAGETYPE_MAXLEN 15
#define PEER_INTERVAL_MS_MAX 3600000

#define PEER_VERSION_MAJOR 0
#define PEER_VERSION_MINOR 1
#define PEER_VERSION_PATCH 0

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
    extern __declspec(thread) int peer_errno;
#elif defined (__CYGWIN__)
#   define PEER_EXPORT
#   define PEER_PRIVATE
    extern __thread int peer_errno;
#else
#   if (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
#       define PEER_PRIVATE __attribute__ ((visibility ("hidden")))
#       define PEER_EXPORT __attribute__ ((visibility ("default")))
#   else
#       define PEER_PRIVATE
#       define PEER_EXPORT
#   endif
    extern __thread int peer_errno;
#endif // __WINDOWS__

// opaque class structure to allow forward references.
typedef struct _peer_t peer_t;
#define PEER_T_DEFINED

#define PEER_DISCOVERY_PORT 5772 // free port in IANA DB

#define PEER_DOMAIN_DEFAULT "peer_global"

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

PEER_EXPORT void peer_private_selftest(bool verbose, const char *subtest);

#ifdef __cplusplus
}
#endif // __cplusplus

#ifndef _Nullable
/**
 * @brief Indicate whether pointer can be NULL.
 * 
 */
#define _Nullable
#endif // _Nullable

#endif // PEER_LIBRARY_H_INCLUDED