#ifndef SESSION_ROUTING_ABI_H
#define SESSION_ROUTING_ABI_H
#include "json_method_abi.h"
#define SR_MAGIC 0x53524d45u
#define SR_SESSION 1u
#define SR_ROUTE 2u
/* getter_result is the field kind. Endpoint contains no native padding. */
struct sr_event {
    struct jm_event field;
    unsigned char address[16];
    unsigned short port, domain;
    jm_u32 endpoint_status;
};
#endif
