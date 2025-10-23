#ifndef CONSTANTS_H
#define CONSTANTS_H

#define MAX_PAYLOAD_SIZE 256

#define SOF_BYTE 0x7F
#define EOF_BYTE 0x7E
#define ESC_BYTE 0x7D

#define ESC_SUB_SOF 0x5F // Replaces a SOF byte in the data
#define ESC_SUB_EOF 0x5E // Replaces an EOF byte in the data
#define ESC_SUB_ESC 0x5D // Replaces an ESC byte in the data

#if defined(PICO_RP2350) || defined(PICO_BOARD_PICO2) || defined(PICO_BOARD_PICO2_W)
#define DEFAULT_STACK_SIZE 512
#else
#define DEFAULT_STACK_SIZE 256
#endif 

#endif