#ifndef CPU_ENDING_H
#define CPU_ENDING_H

//Swap a 16-bit integer
#define SWAPINT16(x) ( \
   (((uint16_t)(x) & 0x00FFU) << 8) | \
   (((uint16_t)(x) & 0xFF00U) >> 8))

//Swap a 32-bit integer
#define SWAPINT32(x) ( \
   (((uint32_t)(x) & 0x000000FFUL) << 24) | \
   (((uint32_t)(x) & 0x0000FF00UL) << 8) | \
   (((uint32_t)(x) & 0x00FF0000UL) >> 8) | \
   (((uint32_t)(x) & 0xFF000000UL) >> 24))

//Swap a 64-bit integer
#define SWAPINT64(x) ( \
   (((uint64_t)(x) & 0x00000000000000FFULL) << 56) | \
   (((uint64_t)(x) & 0x000000000000FF00ULL) << 40) | \
   (((uint64_t)(x) & 0x0000000000FF0000ULL) << 24) | \
   (((uint64_t)(x) & 0x00000000FF000000ULL) << 8) | \
   (((uint64_t)(x) & 0x000000FF00000000ULL) >> 8) | \
   (((uint64_t)(x) & 0x0000FF0000000000ULL) >> 24) | \
   (((uint64_t)(x) & 0x00FF000000000000ULL) >> 40) | \
   (((uint64_t)(x) & 0xFF00000000000000ULL) >> 56))

#endif // CPU_ENDING_H
