// Author: Aaron Snyder
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>

// Helper function declarations
void decodeECN(uint8_t ecn);
void decodeFlags(uint8_t flags);
void decodeTCPFlags(uint8_t flags);

int main(int argc, char* argv[]) {
    // Declare a file pointer and necessary variables
    FILE* filePointer;
    uint8_t byte = 0;
    uint16_t endianValue = 0;
    int ihl = 0;
    int optionWords = 0;
    int payloadBytes = 0;
    int dataOffset = 0;
    int returnInt = 0;
    uint32_t sequenceNumber = 0;
    uint32_t ackNumber = 0;
    int optionsLength = 0;
    uint32_t optionWord = 0;

    // Ensure filename was passed in command line
    if (argc < 2) {
        // Inform user no filename was given
        printf("No filename provided.\n");
        returnInt = 1;
    }
    else {
        // Try to open the file to read
        filePointer = fopen(argv[1], "rb");
        if (!filePointer) {
            // Inform user no file was found
            printf("No file found.\n");
            returnInt = 2;
        }
        else {

            // Ethernet Header
            printf("Ethernet header:\n----------------\n");
            printf("%-33s", "Destination MAC address:");
            fread(&byte, 1, 1, filePointer);
            printf("%02x", byte);
            for (int i = 0; i < 5; i++) {
                fread(&byte, 1, 1, filePointer);
                printf(":");
                printf("%02x", byte);
            }
            printf("\n%-33s", "Source MAC address:");
            fread(&byte, 1, 1, filePointer);
            printf("%02x", byte);
            for (int i = 0; i < 5; i++) {
                fread(&byte, 1, 1, filePointer);
                printf(":");
                printf("%02x", byte);
            }
            printf("\n%-33s", "Type:");
            for (int i = 0; i < 2; i++) {
                fread(&byte, 1, 1, filePointer);
                printf("%02x", byte);
            }
            printf("\n\n");

            // Read IP version and header length
            printf("IPv4 Header:\n-------------\n");
            fread(&byte, 1, 1, filePointer);
            printf("%-33s%02x\n", "Version:", byte >> 4);
            ihl = (byte & 0x0F);
            printf("%-33s%02x\n", "Internet Header Length:", ihl);

            // Read and decode Type of Service byte
            fread(&byte, 1, 1, filePointer);
            printf("%-33s%02x\n", "DSCP:", byte >> 2);

            // Extract and decode ECN bits
            printf("%-33s%02x      ", "ECN:", byte & 0x03);
            decodeECN(byte & 0x03);

            // Read total length field in big-endian order
            fread(&byte, 1, 1, filePointer);
            endianValue = byte << 8;
            fread(&byte, 1, 1, filePointer);
            endianValue |= byte;
            printf("%-33s%d\n", "Total Length:", endianValue);

            // Read identification field in big-endian order and print in decimal
            fread(&byte, 1, 1, filePointer);
            endianValue = byte << 8;
            fread(&byte, 1, 1, filePointer);
            endianValue |= byte;
            printf("%-33s%d\n", "Identification:", endianValue);

            // Read flags and fragment offset, decoding flags and offset separately
            fread(&byte, 1, 1, filePointer);
            endianValue = byte << 8;
            fread(&byte, 1, 1, filePointer);
            endianValue |= byte;
            printf("%-33s", "Flags:");
            decodeFlags(endianValue >> 13);
            printf("%-33s%d\n", "Fragment Offset:", endianValue & 0x1FFF);

            // Read Time to Live and protocol fields
            fread(&byte, 1, 1, filePointer);
            printf("%-33s%d\n", "Time to Live:", byte);

            fread(&byte, 1, 1, filePointer);
            printf("%-33s%d\n", "Protocol:", byte);

            // Read checksum in big-endian order
            fread(&byte, 1, 1, filePointer);
            endianValue = byte << 8;
            fread(&byte, 1, 1, filePointer);
            endianValue |= byte;
            printf("%-33s0x%04x\n", "IP Checksum:", endianValue);

            // Read and print Source IP Address
            printf("%-33s", "Source IP Address:");
            fread(&byte, 1, 1, filePointer);
            printf("%u", byte);
            for (int i = 0; i < 3; i++) {
                fread(&byte, 1, 1, filePointer);
                printf(".");
                printf("%u", byte);
            }

            // Read and print Destination IP Address
            printf("\n%-33s", "Destination IP Address:");
            fread(&byte, 1, 1, filePointer);
            printf("%u", byte);
            for (int i = 0; i < 3; i++) {
                fread(&byte, 1, 1, filePointer);
                printf(".");
                printf("%u", byte);
            }
            printf("\n");

            // Handle IP options if present
            if (ihl > 5) {
                int optionsLength = (ihl * 4) - 20;
                int optionWords = optionsLength / 4;
                for (int i = 0; i < optionWords; i++) {
                    optionWord = 0;
                    for (int j = 0; j < 4; j++) {
                        fread(&byte, 1, 1, filePointer);
                        optionWord = (optionWord << 8) | byte;
                    }
                    printf("Option Word #%-20d0x%08x\n", i, optionWord);
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
            for (int i = 0; i < 4; i++) {
                fread(&byte, 1, 1, filePointer);
                sequenceNumber = (sequenceNumber << 8) | byte;
            }
            printf("%-33s%u\n", "Raw Sequence Number:", sequenceNumber);

            // Raw Acknowledgement Number
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
                    printf("TCP Option Word #%-16d0x%08x\n", i, optionWord);
                }
            }
            else {
                printf("%-33s%s\n", "Options:", "No Options");
            }

            // Read and print payload bytes
            printf("\nPayload:\n");
            while (fread(&byte, 1, 1, filePointer)) {
                printf("%02x ", byte);
                payloadBytes++;
                if (payloadBytes % 32 == 0) {
                    printf("\n");
                }
                else if (payloadBytes % 8 == 0) {
                    printf("  ");
                }
            }

            fclose(filePointer);
        }
    }
    return returnInt;
}

// Helper function implementations
void decodeECN(uint8_t ecn) {
    switch (ecn) {
    case 0:
        printf("Non-ECT Packet\n");
        break;
    case 1:
    case 2:
        printf("ECN-Capable Transport\n");
        break;
    case 3:
        printf("Congestion Experienced\n");
        break;
    default:
        printf("Unknown ECN\n");
        break;
    }
}

// Decode flags field by examining specific bits and print meaning
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

// Decode TCP flags field by examining specific bits and print their meaning
void decodeTCPFlags(uint8_t flags) {
    for (uint8_t i = 0; i < 8; i++) {
        switch (1 << i) {
        case 0x01:
            if (flags & 0x01) printf("FIN ");
            break;
        case 0x02:
            if (flags & 0x02) printf("SYN ");
            break;
        case 0x04:
            if (flags & 0x04) printf("RST ");
            break;
        case 0x08:
            if (flags & 0x08) printf("PSH ");
            break;
        case 0x10:
            if (flags & 0x10) printf("ACK ");
            break;
        case 0x20:
            if (flags & 0x20) printf("URG ");
            break;
        case 0x40:
            if (flags & 0x40) printf("ECE ");
            break;
        case 0x80:
            if (flags & 0x80) printf("CWR ");
            break;
        }
    }
    printf("\n");
}
