/**
 * @file peernet_library.h
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2022-09-18
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef PEERNET_LIBRARY_H_INCLUDED
#define PEERNET_LIBRARY_H_INCLUDED

#define ZYRE_BUILD_DRAFT_API 1
#include <zyre.h>

#define PEERNET_PEER_NAME_MINLEN 4
#define PEERNET_PEER_NAME_MAXLEN 15
#define PEERNET_PEER_GROUP_MINLEN 4
#define PEERNET_PEER_GROUP_MAXLEN 15
#define PEERNET_PEER_MESSAGETYPE_MINLEN 4
#define PEERNET_PEER_MESSAGETYPE_MAXLEN 15
#define PEERNET_INTERVAL_MS_MAX 3600000

#define PEERNET_VERSION_MAJOR 0
#define PEERNET_VERSION_MINOR 1
#define PEERNET_VERSION_PATCH 0

#define PEERNET_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))

#define PEERNET_VERSION \
    PEERNET_MAKE_VERSION(PEERNET_VERSION_MAJOR, PEERNET_VERSION_MINOR, PEERNET_VERSION_PATCH)

#if defined (__WINDOWS__)
#   if defined PEERNET_STATIC
#       define PEERNET_EXPORT
#   elif defined PEERNET_INTERNAL_BUILD
#       if defined DLL_EXPORT
#           define PEERNET_EXPORT __declspec(dllexport)
#       else
#           define PEERNET_EXPORT
#       endif
#   elif defined PEERNET_EXPORTS
#       define PEERNET_EXPORT __declspec(dllexport)
#   else
#       define PEERNET_EXPORT __declspec(dllimport)
#   endif
#   define PEERNET_PRIVATE
    extern __declspec(thread) int peernet_errno;
#elif defined (__CYGWIN__)
#   define PEERNET_EXPORT
#   define PEERNET_PRIVATE
    extern __thread int peernet_errno;
#else
#   if (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
#       define PEERNET_PRIVATE __attribute__ ((visibility ("hidden")))
#       define PEERNET_EXPORT __attribute__ ((visibility ("default")))
#   else
#       define PEERNET_PRIVATE
#       define PEERNET_EXPORT
#   endif
    extern __thread int peernet_errno;
#endif // __WINDOWS__

// opaque class structure to allow forward references.
typedef struct _peer_t peer_t;
#define PEERNET_T_DEFINED

#define PEERNET_DISCOVERY_PORT 5772 // free port in IANA DB

#define PEERNET_DOMAIN_DEFAULT "peernet_global"

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

PEERNET_EXPORT void peernet_private_selftest(bool verbose, const char *subtest);

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

#endif // PEERNET_LIBRARY_H_INCLUDED