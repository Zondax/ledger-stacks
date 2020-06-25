#pragma once

#include <stdint.h>
#include "parser_common.h"
#include "parser_txdef.h"


/******* Address c32-chack encoding **************************************************************/

uint16_t rs_c32_address(const uint8_t *input, uint8_t version, uint8_t *output, uint16_t outLen);

/****************************** others ***********************************************************/

parser_error_t _parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize, uint16_t *alloc_size);

parser_error_t _read(const parser_context_t *c, parser_tx_t *v);

parser_error_t _validate(const parser_context_t *ctx, const parser_tx_t *v);

uint8_t _getNumItems(const parser_context_t *ctx, const parser_tx_t *v);

parser_error_t _getItem(const parser_context_t *ctx,
                              int8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outValue, uint16_t outValueLen,
                              uint8_t pageIdx, uint8_t *pageCount,
                              const parser_tx_t *v);

