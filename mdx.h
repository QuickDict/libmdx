#ifndef MDX_H
#define MDX_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define MDX_EXPORT

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Error codes returned by functions
 */
typedef enum {
    MDX_NO_ERROR = 0,
    MDX_MALLOC_ERROR,
    MDX_FILE_ERROR,
    MDX_CHECKSUM_ERROR,
    MDX_DECRYPT_ERROR,
    MDX_UNCOMPRESS_ERROR,
    MDX_PARSE_ERROR,
    MDX_UNSUPPORTED_VERSION_ERROR,
    MDX_UNKNOWN_ERROR,
} MDX_RET;

typedef enum {
    MDX_UTF8 = 0,
    MDX_UTF16,
    MDX_GBK,
} MDX_ENCODING_TYPE;

typedef enum {
    MDX_Html = 0,
    MDX_Text,
} MDX_FORMAT;

typedef struct
{
    float generated_by_engine_version;
    float required_engine_version;
    int encrypted;
    MDX_ENCODING_TYPE encoding;
    MDX_FORMAT format;
    char *creation_date;
    bool compact;
    bool compat;
    bool key_caseSensitive;
    char *description;
    char *title;
    char *data_source_format;
    char *style_sheet;
    char *register_by;
    char *reg_code;
} mdx_header;

typedef struct
{
    size_t offset;
    uint64_t num_blocks;
    uint64_t num_total_entries;

    unsigned char **keywords;
    size_t *record_offsets;

} mdx_keyword;

typedef struct
{
    size_t offset;
    uint64_t num_blocks;
    uint64_t num_total_entries;

    uint64_t *compressed_block_sizes;
    uint64_t *uncompressed_block_sizes;
    uint64_t *record_block_offsets;
} mdx_record;

typedef struct
{
    mdx_header header;
    mdx_keyword keyword;
    mdx_record record;
} mdx_data;

MDX_EXPORT MDX_RET mdx_init(FILE *fp, mdx_data *data);
MDX_EXPORT MDX_RET mdx_free(mdx_data *data);

MDX_EXPORT MDX_RET mdx_parse_keyword_indexes(FILE *fp, mdx_data *data);
MDX_EXPORT MDX_RET mdx_free_keyword_indexes(mdx_data *data);
MDX_EXPORT MDX_RET mdx_parse_keyword_block(FILE *fp, mdx_data *data, int block);
MDX_EXPORT MDX_RET mdx_free_keyword_block(mdx_data *data, int block);

MDX_EXPORT MDX_RET mdx_parse_record_indexes(FILE *fp, mdx_data *data);
MDX_EXPORT MDX_RET mdx_free_record_indexes(mdx_data *data);
MDX_EXPORT MDX_RET mdx_parse_record_block(FILE *fp, mdx_data *data, int block);
MDX_EXPORT MDX_RET mdx_free_record_block(mdx_data *data, int block);

MDX_EXPORT MDX_RET mdx_decrypt_header(unsigned char *data, size_t len);
MDX_EXPORT MDX_RET mdx_decrypt_indexes(unsigned char *data, size_t len);
MDX_EXPORT MDX_RET mdx_uncompress(unsigned char *compressed,
                                  size_t compressed_length,
                                  unsigned char **uncompressed,
                                  size_t *uncompressed_length);

MDX_EXPORT const char *mdx_error_string(MDX_RET code);
void print_hex(const char *text, const unsigned char *data, int len);

#ifdef __cplusplus
}
#endif

#endif // MDX_H
