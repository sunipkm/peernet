/**
 * @file peer_md5sum_md5sum.h
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2022-09-20
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef __peer_md5sum_MD5SUM_H_INCLUDED__
#define __peer_md5sum_MD5SUM_H_INCLUDED__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../include/peer_library.h"

typedef struct{
	uint64_t size;        // Size of input in bytes
	uint32_t buffer[4];   // Current accumulation of hash
	uint8_t input[64];    // Input to be used in the next step
	uint8_t digest[16];   // Result of algorithm
}peer_md5sum_md5context_t;

PEER_PRIVATE void peer_md5sum_md5Init(peer_md5sum_md5context_t *ctx);
PEER_PRIVATE void peer_md5sum_md5Update(peer_md5sum_md5context_t *ctx, uint8_t *input, size_t input_len);
PEER_PRIVATE void peer_md5sum_md5Finalize(peer_md5sum_md5context_t *ctx);
PEER_PRIVATE void peer_md5sum_md5Step(uint32_t *buffer, uint32_t *input);

PEER_PRIVATE uint8_t* peer_md5sum_md5String(char *input);
PEER_PRIVATE uint8_t* peer_md5sum_md5File(FILE *file);

#endif // __peer_md5sum_MD5SUM_H_INCLUDED__