// PacketDecode2.cpp
// Author: Aaron Snyder
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>

// Helper function declarations
void decodeECN(uint8_t ecn);
void decodeFlags(uint8_t flags);
void decodeTCPFlags(uint8_t flags);

int main(int argc, char* argv[]) {
    FILE* filePointer = NULL;
    uint8_t byte = 0;
    uint16_t endianValue = 0;
    int ihl = 0;
    int optionWords = 0;
    int optionBytes = 0;
    int payloadBytes = 0;
    int dataOffset = 0;
    int returnInt = 0;
    uint32_t sequenceNumber = 0;
    uint32_t ackNumber = 0;
    int optionsLength = 0;
    uint32_t optionWord = 0;

    // Open the file
    if (argc < 2) {
        printf("No filename provided.\n");
        returnInt = 1;
    }
    else {
        filePointer = fopen(argv[1], "rb");
        if (!filePointer) {
            printf("No file found.\n");
            returnInt = 2;
        }
        else {
            // Ethernet Header
            printf("Ethernet header:\n----------------\n");
            printf("%-33s", "Destination MAC address:");
            for (int i = 0; i < 6; i++) {
                fread(&byte, 1, 1, filePointer);
                printf("%02x", byte);
                if (i < 5) printf(":");
            }
            printf("\n%-33s", "Source MAC address:");
            for (int i = 0; i < 6; i++) {
                fread(&byte, 1, 1, filePointer);
                printf("%02x", byte);
                if (i < 5) printf(":");
            }
            printf("\n%-33s", "Type:");
            for (int i = 0; i < 2; i++) {
                fread(&byte, 1, 1, filePointer);
                printf("%02x", byte);
            }
            printf("\n\n");

            // IPv4 Header
            printf("IPv4 Header:\n-------------\n");
            fread(&byte, 1, 1, filePointer);
            printf("%-33s%u\n", "Version:", byte >> 4);
            ihl = (byte & 0x0F);
            printf("%-33s%d\n", "Internet Header Length:", ihl);

            fread(&byte, 1, 1, filePointer);
            printf("%-33s%02x\n", "DSCP:", byte >> 2);

            // Extract and decode ECN bits
            printf("%-33s%02x ", "ECN:", byte & 0x03);
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
                optionWords = (ihl - 20) / 4;
                for (int i = 0; i < optionWords; i++) {
                    optionWord = 0;
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

            // TCP Header
            printf("\nTCP Header:\n-----------\n");

            // Source port
            fread(&byte, 1, 1, filePointer);
            endianValue = byte << 8;
            fread(&byte, 1, 1, filePointer);
            endianValue |= byte;
            printf("%-33s%d\n", "Source Port:", endianValue);

            // Destination port
            fread(&byte, 1, 1, filePointer);
            endianValue = byte << 8;
            fread(&byte, 1, 1, filePointer);
            endianValue |= byte;
            printf("%-33s%d\n", "Destination Port:", endianValue);

            // Raw sequence number
            sequenceNumber = 0;
            for (int i = 0; i < 4; i++) {
                fread(&byte, 1, 1, filePointer);
                sequenceNumber = (sequenceNumber << 8) | byte;
            }
            printf("%-33s%u\n", "Raw Sequence Number:", sequenceNumber);

            // Raw Acknowledgement Number
            ackNumber = 0;
            for (int i = 0; i < 4; i++) {
                fread(&byte, 1, 1, filePointer);
                ackNumber = (ackNumber << 8) | byte;
            }
            printf("%-33s%u\n", "Raw Acknowledgement Number:", ackNumber);

            // Flags
            fread(&byte, 1, 1, filePointer);
            dataOffset = (byte >> 4);
            printf("%-33s%d\n", "Data Offset:", dataOffset);

            fread(&byte, 1, 1, filePointer);
            printf("%-33s", "Flags:");
            decodeTCPFlags(byte);

            // Window size
            fread(&byte, 1, 1, filePointer);
            endianValue = byte << 8;
            fread(&byte, 1, 1, filePointer);
            endianValue |= byte;
            printf("%-33s%d\n", "Window Size:", endianValue);

            // Checksum
            fread(&byte, 1, 1, filePointer);
            endianValue = byte << 8;
            fread(&byte, 1, 1, filePointer);
            endianValue |= byte;
            printf("%-33s0x%04x\n", "TCP Checksum:", endianValue);

            // Urgent Pointer
            fread(&byte, 1, 1, filePointer);
            endianValue = byte << 8;
            fread(&byte, 1, 1, filePointer);
            endianValue |= byte;
            printf("%-33s%d\n", "Urgent Pointer:", endianValue);

            // Options
            if (dataOffset > 5) {
                optionsLength = (dataOffset * 4) - 20;
                optionWords = optionsLength / 4;

                // Print each 4-byte option word
                for (int i = 0; i < optionWords; i++) {
                    optionWord = 0;
                    for (int j = 0; j < 4; j++) {
                        fread(&byte, 1, 1, filePointer);
                        optionWord = (optionWord << 8) | byte;
                    }
                    printf("TCP Option Word #%d: 0x%08x\n", i, optionWord);
                }
            }
            else {
                printf("%-33s%s\n", "TCP Options:", "No Options");
            }

            // Payload
            printf("\nPayload:\n");
            while (fread(&byte, 1, 1, filePointer)) {
                printf("%02x ", byte);
                payloadBytes++;
                if (payloadBytes % 32 == 0) printf("\n");
            }
            if (payloadBytes % 32 != 0) printf("\n");

            fclose(filePointer);
        }
    }
    return returnInt;
}

// Helper function implementations
void decodeECN(uint8_t ecn) {
    if (ecn == 0) printf("Non-ECT Packet\n");
    else if (ecn == 1 || ecn == 2) printf("ECN-Capable Transport\n");
    else if (ecn == 3) printf("Congestion Experienced\n");
    else printf("Unknown ECN\n");
}

void decodeFlags(uint8_t flags) {
    if (flags & 0x2) printf("Don't Fragment\n");
    else if (flags & 0x1) printf("More Fragments\n");
    else printf("No Flag Set\n");
}

void decodeTCPFlags(uint8_t flags) {
    if (flags & 0x01) printf("FIN ");
    if (flags & 0x02) printf("SYN ");
    if (flags & 0x04) printf("RST ");
    if (flags & 0x08) printf("PSH ");
    if (flags & 0x10) printf("ACK ");
    if (flags & 0x20) printf("URG ");
    if (flags & 0x40) printf("ECE ");
    if (flags & 0x80) printf("CWR ");
    printf("\n");
}
