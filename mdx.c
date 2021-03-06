#include "mdx.h"
#include "cpu_ending.h"
#include "ripemd128.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_MINIZ
#define uncompress mz_uncompress
#include "miniz.h"
#else
#include <zlib.h>
#endif

static const char *MDX_ERROR_STRING[] = {
    "No error",
    "Malloc error",
    "File error",
    "Checksum error",
    "Decrypt error",
    "Uncompress error",
    "Parse error",
    "Unsupported version error",
    "Unknown error",
};

MDX_RET mdx_init(FILE *fp, mdx_data *data)
{
    fseek(fp, 0, SEEK_SET);

    uint32_t str_len;
    if (fread(&str_len, sizeof(str_len), 1, fp) == 0)
        return MDX_FILE_ERROR;
    str_len = SWAPINT32(str_len);
    char *property_str = (char *) malloc(str_len);
    if (property_str == NULL)
        return MDX_MALLOC_ERROR;
    if (fread(property_str, str_len, 1, fp) == 0)
        return MDX_FILE_ERROR;

    uint32_t checksum;
    if (fread(&checksum, sizeof(checksum), 1, fp) == 0)
        return MDX_FILE_ERROR;
    // TODO: check checksum

    // TODO: parse property_str
    free(property_str);
    data->header.creation_date = NULL;
    data->header.title = NULL;
    data->header.description = NULL;
    data->header.data_source_format = NULL;
    data->header.style_sheet = NULL;
    data->header.register_by = NULL;
    data->header.reg_code = NULL;
    data->header.encrypted = 2;
    data->header.generated_by_engine_version = 2.0;
    data->header.required_engine_version = 2.0;
    data->header.encoding = MDX_UTF8;

    data->keyword.offset = ftell(fp);
    data->keyword.keywords = NULL;
    data->keyword.record_offsets = NULL;

    // TODO: possibly encrypted!
    fseek(fp, 8 + 8 + 8, SEEK_CUR);
    uint64_t indexes_compressed_length;
    uint64_t block_compressed_length;
    if (fread(&indexes_compressed_length, sizeof(indexes_compressed_length), 1, fp) == 0)
        return MDX_FILE_ERROR;
    indexes_compressed_length = SWAPINT64(indexes_compressed_length);
    if (fread(&block_compressed_length, sizeof(block_compressed_length), 1, fp) == 0)
        return MDX_FILE_ERROR;
    block_compressed_length = SWAPINT64(block_compressed_length);

    data->record.offset = data->keyword.offset + 8 * 5 + 4 + indexes_compressed_length + block_compressed_length;

    data->record.compressed_block_sizes = NULL;
    data->record.uncompressed_block_sizes = NULL;
    data->record.record_block_offsets = NULL;

    return MDX_NO_ERROR;
}

MDX_RET mdx_free(mdx_data *data)
{
    if (data->header.creation_date != NULL) {
        free(data->header.creation_date);
        data->header.creation_date = NULL;
    }
    if (data->header.title != NULL) {
        free(data->header.title);
        data->header.title = NULL;
    }
    if (data->header.description != NULL) {
        free(data->header.description);
        data->header.description = NULL;
    }
    if (data->header.data_source_format != NULL) {
        free(data->header.data_source_format);
        data->header.data_source_format = NULL;
    }
    if (data->header.style_sheet != NULL) {
        free(data->header.style_sheet);
        data->header.style_sheet = NULL;
    }
    if (data->header.register_by != NULL) {
        free(data->header.register_by);
        data->header.register_by = NULL;
    }
    if (data->header.reg_code != NULL) {
        free(data->header.reg_code);
        data->header.reg_code = NULL;
    }

    mdx_free_keyword_indexes(data);
    mdx_free_record_indexes(data);

    return MDX_NO_ERROR;
}

MDX_RET mdx_parse_keyword_indexes(FILE *fp, mdx_data *data)
{
    fseek(fp, data->keyword.offset, SEEK_SET);

    if (fread(&data->keyword.num_blocks, sizeof(data->keyword.num_blocks), 1, fp) == 0)
        return MDX_FILE_ERROR;
    data->keyword.num_blocks = SWAPINT64(data->keyword.num_blocks);

    if (fread(&data->keyword.num_total_entries, sizeof(data->keyword.num_total_entries), 1, fp) == 0)
        return MDX_FILE_ERROR;
    data->keyword.num_total_entries = SWAPINT64(data->keyword.num_total_entries);

    uint64_t indexes_uncompressed_length;
    if (fread(&indexes_uncompressed_length, sizeof(indexes_uncompressed_length), 1, fp) == 0)
        return MDX_FILE_ERROR;
    indexes_uncompressed_length = SWAPINT64(indexes_uncompressed_length);

    uint64_t indexes_compressed_length;
    if (fread(&indexes_compressed_length, sizeof(indexes_compressed_length), 1, fp) == 0)
        return MDX_FILE_ERROR;
    indexes_compressed_length = SWAPINT64(indexes_compressed_length);

    uint64_t block_length;
    if (fread(&block_length, sizeof(block_length), 1, fp) == 0)
        return MDX_FILE_ERROR;
    block_length = SWAPINT64(block_length);

    uint32_t checksum;
    if (fread(&checksum, sizeof(checksum), 1, fp) == 0)
        return MDX_FILE_ERROR;
    checksum = SWAPINT32(checksum);

    unsigned char *indexes_compressed = (unsigned char *) malloc(indexes_compressed_length);
    if (indexes_compressed == NULL)
        return MDX_MALLOC_ERROR;
    if (fread(indexes_compressed, indexes_compressed_length, 1, fp) == 0)
        return MDX_FILE_ERROR;
    if (data->header.encrypted & 0x2) {
        MDX_RET ret = mdx_decrypt_indexes(indexes_compressed, indexes_compressed_length);
        if (ret != MDX_NO_ERROR)
            return ret;
    }
    unsigned char *indexes_uncompressed = (unsigned char *) malloc(indexes_uncompressed_length);
    if (indexes_uncompressed == NULL)
        return MDX_MALLOC_ERROR;
    if (uncompress(indexes_uncompressed,
                   &indexes_uncompressed_length,
                   indexes_compressed + 8,
                   indexes_compressed_length - 8)
        != Z_OK) {
        free(indexes_compressed);
        free(indexes_uncompressed);
        return MDX_UNCOMPRESS_ERROR;
    }
    free(indexes_compressed);

    size_t byte_count = 0;
    size_t block = 0;
    uint64_t *block_compressed_length = malloc(data->keyword.num_blocks * sizeof(uint64_t));
    uint64_t *block_uncompressed_length = malloc(data->keyword.num_blocks * sizeof(uint64_t));
    while (block < data->keyword.num_blocks && byte_count < indexes_uncompressed_length) {
        uint64_t num_block_entries = SWAPINT64(*(uint64_t *) (indexes_uncompressed + byte_count));
        byte_count += sizeof(num_block_entries);

        uint16_t block_first_word_length = SWAPINT16(*(uint16_t *) (indexes_uncompressed + byte_count));
        byte_count += sizeof(block_first_word_length);
        byte_count += block_first_word_length + 1; // skip first word

        uint16_t block_last_word_length = SWAPINT16(*(uint16_t *) (indexes_uncompressed + byte_count));
        byte_count += sizeof(block_last_word_length);
        byte_count += block_last_word_length + 1; // skip last word

        block_compressed_length[block] = SWAPINT64(*(uint64_t *) (indexes_uncompressed + byte_count));
        byte_count += sizeof(uint64_t);
        block_uncompressed_length[block] = SWAPINT64(*(uint64_t *) (indexes_uncompressed + byte_count));
        byte_count += sizeof(uint64_t);
        ++block;
    }
    free(indexes_uncompressed);
    if (block != data->keyword.num_blocks || byte_count != indexes_uncompressed_length)
        return MDX_PARSE_ERROR;

    data->keyword.record_offsets = malloc(data->keyword.num_total_entries * sizeof(uint64_t));
    data->keyword.keywords = malloc(data->keyword.num_total_entries * sizeof(unsigned char *));
    size_t entry_count = 0;
    for (block = 0; block < data->keyword.num_blocks; ++block) {
        unsigned char *block_compressed = (unsigned char *) malloc(block_compressed_length[block]);
        unsigned char *block_uncompressed = (unsigned char *) malloc(block_uncompressed_length[block]);
        if (fread(block_compressed, 1, block_compressed_length[block], fp) != block_compressed_length[block]) {
            return MDX_FILE_ERROR;
        }

        size_t uncompressed_length = block_uncompressed_length[block];
        if (mdx_uncompress(block_compressed, block_compressed_length[block], &block_uncompressed, &uncompressed_length)
            != MDX_NO_ERROR) {
            return MDX_UNCOMPRESS_ERROR;
        }

        int start = 0;
        uint64_t end = 0;
        while (end < block_uncompressed_length[block]) {
            start = end;
            data->keyword.record_offsets[entry_count] = SWAPINT64(*(uint64_t *) (block_uncompressed + start));
            end = start + sizeof(uint64_t);
            // FIXME: two-bytes null terminator for utf-16 encoding
            while (end < block_uncompressed_length[block] && block_uncompressed[end++] != 0x00 /* null-terminator */) {
            }
            data->keyword.keywords[entry_count] = malloc(end - start);
            memcpy(data->keyword.keywords[entry_count], block_uncompressed + start + 8, end - start - 8);
            ++entry_count;
        }

        free(block_compressed);
        free(block_uncompressed);
    }
    assert(entry_count == data->keyword.num_total_entries);

    free(block_compressed_length);
    free(block_uncompressed_length);

    return MDX_NO_ERROR;
}

MDX_RET mdx_free_keyword_indexes(mdx_data *data)
{
    if (data->keyword.record_offsets != NULL) {
        free(data->keyword.record_offsets);
        data->keyword.record_offsets = NULL;
    }
    if (data->keyword.keywords != NULL) {
        for (uint64_t i = 0; i < data->keyword.num_total_entries; ++i)
            free(data->keyword.keywords[i]);
        data->keyword.keywords = NULL;
    }
    return MDX_NO_ERROR;
}

MDX_RET mdx_parse_keyword_block(FILE *fp, mdx_data *data, int block)
{
    // TODO
    return MDX_NO_ERROR;
}

MDX_RET mdx_free_keyword_block(mdx_data *data, int block)
{
    // TODO
    return MDX_NO_ERROR;
}

MDX_RET mdx_parse_record_indexes(FILE *fp, mdx_data *data)
{
    fseek(fp, data->record.offset, SEEK_SET);

    if (fread(&data->record.num_blocks, sizeof(data->record.num_blocks), 1, fp) == 0)
        return MDX_FILE_ERROR;
    data->record.num_blocks = SWAPINT64(data->record.num_blocks);

    if (fread(&data->record.num_total_entries, sizeof(data->record.num_total_entries), 1, fp) == 0)
        return MDX_FILE_ERROR;
    data->record.num_total_entries = SWAPINT64(data->record.num_total_entries);

    uint64_t indexes_length;
    if (fread(&indexes_length, sizeof(indexes_length), 1, fp) == 0)
        return MDX_FILE_ERROR;
    indexes_length = SWAPINT64(indexes_length);

    uint64_t records_length;
    if (fread(&records_length, sizeof(records_length), 1, fp) == 0)
        return MDX_FILE_ERROR;
    records_length = SWAPINT64(records_length);

    data->record.compressed_block_sizes = malloc(data->record.num_blocks * sizeof(uint64_t));
    data->record.uncompressed_block_sizes = malloc(data->record.num_blocks * sizeof(uint64_t));
    data->record.record_block_offsets = malloc(data->record.num_blocks * sizeof(uint64_t));
    size_t accumulated_length = 0;
    for (size_t block = 0; block < data->record.num_blocks; ++block) {
        fread(&data->record.compressed_block_sizes[block], sizeof(uint64_t), 1, fp);
        data->record.compressed_block_sizes[block] = SWAPINT64(data->record.compressed_block_sizes[block]);
        fread(&data->record.uncompressed_block_sizes[block], sizeof(uint64_t), 1, fp);
        data->record.uncompressed_block_sizes[block] = SWAPINT64(data->record.uncompressed_block_sizes[block]);
        data->record.record_block_offsets[block] = data->record.offset + 8 + 8 + 8 + 8 + indexes_length
                                                   + accumulated_length;
        accumulated_length += data->record.compressed_block_sizes[block];
    }

    return MDX_NO_ERROR;
}

MDX_RET mdx_free_record_indexes(mdx_data *data)
{
    if (data->record.compressed_block_sizes != NULL) {
        free(data->record.compressed_block_sizes);
        data->record.compressed_block_sizes = NULL;
    }
    if (data->record.uncompressed_block_sizes != NULL) {
        free(data->record.uncompressed_block_sizes);
        data->record.uncompressed_block_sizes = NULL;
    }
    if (data->record.record_block_offsets != NULL) {
        free(data->record.record_block_offsets);
        data->record.record_block_offsets = NULL;
    }
    return MDX_NO_ERROR;
}

MDX_RET mdx_parse_record_block(FILE *fp, mdx_data *data, int block)
{
    // TODO
    return MDX_NO_ERROR;
}

MDX_RET mdx_free_record_block(mdx_data *data, int block)
{
    // TODO
    return MDX_NO_ERROR;
}

MDX_RET mdx_decrypt_header(unsigned char *data, size_t len)
{
    // TODO
    return MDX_NO_ERROR;
}

MDX_RET mdx_decrypt_indexes(unsigned char *data, size_t len)
{
    unsigned char key[8];
    memcpy(key, data + 4, 4); // checksum
    *(unsigned int *) (key + 4) = 0x00003695;
    uint8_t digest[RIPEMD128_DIGEST_SIZE];
    if (ripemd128Compute(key, 8, digest) != 0)
        return MDX_DECRYPT_ERROR;

    // decryption
    unsigned char previous = 0x36;
    unsigned char *compressed = data + 8; // start of compressed data
    for (size_t i = 0; i < len - 8; ++i) {
        unsigned char t = (compressed[i] >> 4 | compressed[i] << 4) & 0xff;
        t = t ^ previous ^ (i & 0xff) ^ digest[i % RIPEMD128_DIGEST_SIZE];
        previous = compressed[i];
        compressed[i] = t;
    }

    return MDX_NO_ERROR;
}

MDX_RET mdx_uncompress(unsigned char *compressed,
                       size_t compressed_length,
                       unsigned char **uncompressed,
                       size_t *uncompressed_length)
{
    uint32_t compression_type = *(uint32_t *) compressed;
    uint32_t checksum = SWAPINT32(*(uint32_t *) (compressed + sizeof(compression_type)));

    MDX_RET ret = MDX_NO_ERROR;
    if (compression_type == 0x00000000) {
        memcpy(uncompressed, compressed + sizeof(compression_type) + sizeof(checksum), *uncompressed_length);
    } else if (compression_type == 0x00000001) {
        // TODO
        ret = MDX_UNCOMPRESS_ERROR;
    } else if (compression_type == 0x00000002) {
        if (uncompress(*uncompressed, uncompressed_length, compressed + 8, compressed_length - 8) != Z_OK) {
            ret = MDX_UNCOMPRESS_ERROR;
        }
    } else {
        ret = MDX_UNCOMPRESS_ERROR;
    }
    return ret;
}

const char *mdx_error_string(MDX_RET code)
{
    if (code < MDX_NO_ERROR || code > MDX_UNKNOWN_ERROR)
        code = MDX_UNKNOWN_ERROR;
    return MDX_ERROR_STRING[code];
}

void print_hex(const char *text, const unsigned char *data, int len)
{
    if (text != NULL)
        printf("%s", text);
    for (int i = 0; i < len; ++i) {
        if (i % 8 == 0)
            printf(" ");
        printf("%02x", data[i]);
    }
    printf("\n");
}
