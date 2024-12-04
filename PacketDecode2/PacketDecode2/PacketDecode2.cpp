// Author: Aaron Snyder
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>

// Helper function declarations
void decodeECN(uint8_t ecn);
void decodeFlags(uint8_t flags);

int main(int argc, char* argv[]) {
    // Only necessary variables
    int ihl = 0;  // Internet Header Length
    int endianValue = 0;  // Used for big-endian to little-endian conversion

    // Open the file
    FILE* filePointer;
    if (argc < 2) {
        printf("No filename provided.\n");
        return 1;
    }
    filePointer = fopen(argv[1], "rb");
    if (!filePointer) {
        printf("No file found.\n");
        return 2;
    }

    // Ethernet Header
    printf("Ethernet header:\n----------------\n");
    printf("%-33s", "Destination MAC address:");
    for (int i = 0; i < 6; i++) {
        uint8_t byte;
        fread(&byte, 1, 1, filePointer);
        printf("%02x", byte);
        if (i < 5) printf(":");
    }
    printf("\n%-33s", "Source MAC address:");
    for (int i = 0; i < 6; i++) {
        uint8_t byte;
        fread(&byte, 1, 1, filePointer);
        printf("%02x", byte);
        if (i < 5) printf(":");
    }
    printf("\n%-33s", "Type:");
    for (int i = 0; i < 2; i++) {
        uint8_t byte;
        fread(&byte, 1, 1, filePointer);
        printf("%02x", byte);
    }
    printf("\n\n");

    // IPv4 Header
    printf("IPv4 Header:\n-------------\n");
    uint8_t byte;
    fread(&byte, 1, 1, filePointer);
    printf("%-33s%u\n", "Version:", byte >> 4);
    ihl = (byte & 0x0F) * 4;
    printf("%-33s%d bytes\n", "Internet Header Length:", ihl);

    fread(&byte, 1, 1, filePointer);
    printf("%-33s%02x\n", "DSCP:", byte >> 2);
    decodeECN(byte & 0x03);

    fread(&byte, 1, 1, filePointer);
    endianValue = byte << 8;
    fread(&byte, 1, 1, filePointer);
    endianValue |= byte;
    printf("%-33s%d\n", "Total Length:", endianValue);

    fread(&byte, 1, 1, filePointer);
    endianValue = byte << 8;
    fread(&byte, 1, 1, filePointer);
    endianValue |= byte;
    printf("%-33s%d\n", "Identification:", endianValue);

    fread(&byte, 1, 1, filePointer);
    endianValue = byte << 8;
    fread(&byte, 1, 1, filePointer);
    endianValue |= byte;
    printf("%-33s", "Flags:");
    decodeFlags(endianValue >> 13);
    printf("%-33s%d\n", "Fragment Offset:", endianValue & 0x1FFF);

    fread(&byte, 1, 1, filePointer);
    printf("%-33s%d\n", "Time to Live:", byte);

    fread(&byte, 1, 1, filePointer);
    printf("%-33s%d\n", "Protocol:", byte);

    fread(&byte, 1, 1, filePointer);
    endianValue = byte << 8;
    fread(&byte, 1, 1, filePointer);
    endianValue |= byte;
    printf("%-33s0x%04x\n", "IP Checksum:", endianValue);

    printf("%-33s", "Source IP Address:");
    for (int i = 0; i < 4; i++) {
        fread(&byte, 1, 1, filePointer);
        printf("%u", byte);
        if (i < 3) printf(".");
    }
    printf("\n%-33s", "Destination IP Address:");
    for (int i = 0; i < 4; i++) {
        fread(&byte, 1, 1, filePointer);
        printf("%u", byte);
        if (i < 3) printf(".");
    }
    printf("\n");

    // Options (if present)
    if (ihl > 20) {
        printf("\nOptions:\n");
        int optionWords = (ihl - 20) / 4;
        for (int i = 0; i < optionWords; i++) {
            uint32_t optionWord = 0;
            for (int j = 0; j < 4; j++) {
                fread(&byte, 1, 1, filePointer);
                optionWord = (optionWord << 8) | byte;
            }
            printf("Option Word #%d: 0x%08x\n", i + 1, optionWord);
        }
    }
    else {
        printf("%-33s%s\n", "Options:", "No Options");
    }

    // Payload
    printf("\nPayload:\n");
    int payloadBytes = 0;
    while (fread(&byte, 1, 1, filePointer)) {
        printf("%02x ", byte);
        payloadBytes++;
        if (payloadBytes % 32 == 0) printf("\n");
    }
    printf("\n");

    fclose(filePointer);
    return 0;
}

// Decode and print description of ECN field
void decodeECN(uint8_t ecn) {
    switch (ecn) {
    case 0: printf("Non-ECT Packet\n"); break;
    case 1:
    case 2: printf("ECN-Capable Transport\n"); break;
    case 3: printf("Congestion Experienced\n"); break;
    default: printf("Unknown ECN\n"); break;
    }
}

// Decode flags field
void decodeFlags(uint8_t flags) {
    if (flags & 0x2) {
        printf("Don't Fragment\n");
    }
    else if (flags & 0x1) {
        printf("More Fragments\n");
    }
    else {
        printf("No Flag Set\n");
    }
}
