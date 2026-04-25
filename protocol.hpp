#pragma once

#define MAX_PAYLOAD_SIZE 2048
#define CH_MAGIC_WORD 0xDEADBEEF

enum CH_CMD {
    CH_CMD_CRASH_CLIENT = 1,
    CH_CMD_SET_GUID = 2,
    CH_INFO_PLAYER_DATA = 3,
    CH_CMD_CONNECT_SERVER = 4,
    CH_CMD_REQUEST_GUID = 5,
    CH_CMD_REQUEST_SCAN = 6,
    CH_CMD_REQUEST_PLAYER_LIST = 7,
    CH_CMD_SET_PLAYER_LIST = 8,
    CH_CMD_REQUEST_FAIRSHOT = 9,
    CH_CMD_FAIRSHOT_ACK = 10,
    CH_CMD_REQUEST_STATE = 11
};

struct CH_Packet {
    unsigned int magic;
    unsigned int type;
    unsigned int size;
    unsigned char payload[MAX_PAYLOAD_SIZE + 1];
};

#pragma pack(push, 1)
typedef struct {
    int inGame;
    int playerNum;
    char name[64];
    char server[60];
} CH_PlayerDataPayload;
#pragma pack(pop)