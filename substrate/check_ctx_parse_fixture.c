/* Fixture for check-ctx-parse. NOT A CLAIM ABOUT TMM.
 *
 * Its only job is to be a compiled artifact with real DWARF, so mk_ctx_parse.py and
 * ls_ctx_parse_sane can be exercised on a host that has neither TMM's debuginfo nor its source.
 * The PRODUCT path derives from TMM's own build artifact and nothing here is consulted there.
 *
 * It carries the shapes that make the derivation non-trivial and that have already produced wrong
 * answers: an 8-bit enum bitfield sitting inside a 4-byte storage unit at a different byte than
 * an address-of would report, a packed struct whose trailing member is defined elsewhere so the
 * layout cannot be printed as a whole, and a run of single-bit flags whose count IS the mask.
 */
typedef unsigned char BYTE; typedef unsigned short UINT16;
typedef unsigned int UINT32; typedef unsigned long long UINT64; typedef int BOOL;

enum parse_state { PARSE_BEGIN = 0, PARSE_METHOD, PARSE_HEADER_NAME, PARSE_INVALID };

struct http_parser;                       /* deliberately incomplete */

struct http_parse_ctx {
    struct http_parser *parser;
    UINT16 max_header_count;
    enum parse_state state : 8;           /* the bitfield trap: byte 10, unit at 8 */
    BYTE flags;
    BYTE version_num;
    BOOL reqresp : 1; BOOL output_header : 1; BOOL header_block : 1;
    UINT32 pt; UINT32 offset; UINT32 reqresp_pos; UINT32 data_offset; UINT64 data;
    UINT64 pad[3];
};

struct tm_header_cache { char blob[400]; };

struct http_parse_info {
    BOOL is_trailer : 1; BOOL is_request : 1; BOOL is_crlf : 1; BOOL lws_found : 1;
    unsigned version : 2; unsigned original_version : 2;
    BYTE method; UINT16 header_count; UINT32 body_pos; int status_code;
    UINT32 f_invalid_method : 1; UINT32 f_invalid_scheme : 1; UINT32 f_invalid_path : 1;
    UINT32 f_invalid_status : 1; UINT32 f_invalid_authority : 1; UINT32 reserved : 27;
    struct tm_header_cache cache;
} __attribute__((packed));

struct http_parse_ctx  g_ctx;
struct http_parse_info g_info;
enum parse_state       g_state;
int main(void) { return (int)(sizeof g_ctx + sizeof g_info + (int)g_state); }
