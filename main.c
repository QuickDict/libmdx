#include "mdx.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    if (argc < 2)
        return 0;

    mdx_data data;
    FILE *fp = fopen(argv[1], "rb");

    printf("parsing header...\n");
    MDX_RET ret = mdx_init(fp, &data);
    if (ret != MDX_NO_ERROR) {
        printf("parse header error: %s.\n", mdx_error_string(ret));
    }

    printf("parsing keywords...\n");
    ret = mdx_parse_keyword_indexes(fp, &data);
    if (ret != MDX_NO_ERROR) {
        printf("parse keyword indexes error: %s.\n", mdx_error_string(ret));
    }

    printf("parsing record...\n");
    ret = mdx_parse_record_indexes(fp, &data);
    if (ret != MDX_NO_ERROR) {
        printf("parse record indexes error: %s.\n", mdx_error_string(ret));
    }

    uint64_t *entry_blocks = malloc(data.keyword.num_total_entries * sizeof(uint64_t));
    size_t *entry_block_relative_offsets = malloc(data.keyword.num_total_entries * sizeof(size_t));

    size_t accumulated_length = 0;
    size_t entry_count = 0;
    for (size_t block = 0; block < data.record.num_blocks; ++block) {
        while (data.keyword.record_offsets[entry_count]
                   < accumulated_length + data.record.uncompressed_block_sizes[block]
               && entry_count < data.keyword.num_total_entries) {
            entry_blocks[entry_count] = block;
            entry_block_relative_offsets[entry_count] = data.keyword.record_offsets[entry_count] - accumulated_length;
            ++entry_count;
        }
        accumulated_length += data.record.uncompressed_block_sizes[block];
    }

    int entry;
    printf("\nentry number: ");
    while (scanf("%d", &entry) == 1) {
        size_t entry_number = entry;
        size_t block = entry_blocks[entry_number];
        const unsigned char *keyword = data.keyword.keywords[entry_number];
        printf("record for entry %s (%lu:%lu)\n",
               keyword,
               data.record.compressed_block_sizes[block],
               data.record.uncompressed_block_sizes[block]);
        unsigned char *block_compressed = (unsigned char *) malloc(data.record.compressed_block_sizes[block]);
        printf("offset of block %lu: %lu\n", block, data.record.record_block_offsets[block]);
        fseek(fp, data.record.record_block_offsets[block], SEEK_SET);
        if (fread(block_compressed, 1, data.record.compressed_block_sizes[block], fp)
            != data.record.compressed_block_sizes[block]) {
            printf("malloc error\n");
        }
        unsigned char *block_uncompressed = (unsigned char *) malloc(data.record.uncompressed_block_sizes[block]);
        ret = mdx_uncompress(block_compressed,
                             data.record.compressed_block_sizes[block],
                             &block_uncompressed,
                             &data.record.uncompressed_block_sizes[block]);
        if (ret != MDX_NO_ERROR) {
            printf("parse record indexes error: %s.\n", mdx_error_string(ret));
        }
        printf("result: %s\n", block_uncompressed + entry_block_relative_offsets[entry_number]);
        printf("\nentry number: ");
    }

    return 0;
}
