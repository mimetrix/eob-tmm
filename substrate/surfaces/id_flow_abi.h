#ifndef ID_FLOW_ABI_H
#define ID_FLOW_ABI_H
#include "message_id_abi.h"
#define IF_MAGIC 0x4944464cu
#define IF_COMPLETE 1u
#define IF_OUT_OF_SCOPE 2u
#define IF_READ_FAILED 3u
#define IF_INVALID 4u
#define IF_BUDGET 5u
#define IF_SIDE_SHIFT 4u
#define IF_STATUS_SHIFT 8u
#define IF_ALLOWED_FLAGS 0x073fu
#endif
