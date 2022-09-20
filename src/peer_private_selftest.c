/*  =========================================================================
    peer_private_selftest.c - run private classes selftests

    Runs all private classes selftests.

    -------------------------------------------------------------------------
    LICENSE FOR THIS PROJECT IS NOT DEFINED!

    Copyright (C) 2022- by peer Developers <zeromq-dev@lists.zeromq.org>

    Please edit license.xml and populate the 'license' tag with proper
    copyright and legalese contents, and regenerate the zproject.

    LICENSE FOR THIS PROJECT IS NOT DEFINED!

################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
    =========================================================================
*/

#include "peer_classes.h"


//  -------------------------------------------------------------------------
//  Run all private classes tests.
//

void
peer_private_selftest (bool verbose, const char *subtest)
{
// Tests for stable private classes:
    if (streq (subtest, "$ALL") || streq (subtest, "peer_md5sum_test"))
        peer_md5sum_test (verbose);
}
/*
################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
*/
