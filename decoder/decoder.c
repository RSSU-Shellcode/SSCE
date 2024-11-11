#pragma warning(disable: 4255)

typedef unsigned char byte;
typedef unsigned int  uint;

void decrypt(byte* data, uint dataLen, byte* key, uint keyLen);
void clean(byte* data, uint len);

// prevent incorrect optimization of the number of parameters
#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain() {
    byte sc0[]  = { 's', 'c' };
    byte key0[] = { 'k', 'e', 'y' };
    decrypt(sc0, 2, key0, 3);
    clean(sc0, 2);

    byte sc1[]  = { 's', 'c', '1'};
    byte key1[] = { 'k', 'e', 'y', '1'};
    decrypt(sc1, 3, key1, 4);
    clean(sc1, 3);
    return sc0[0] + sc1[0];
}

__declspec(noinline)
void decrypt(byte* data, uint dataLen, byte* key, uint keyLen)
{
    byte last = 0xFF;
    uint keyIdx = 0;
    for (uint i = 0; i < dataLen; i++)
    {
        byte b = *data ^ last;
        b ^= *(key + keyIdx);
        last = *data;
        *data = b;
        // update key index
        keyIdx++;
        if (keyIdx >= keyLen)
        {
            keyIdx = 0;
        }
        // update data address
        data++;
    }
}

__declspec(noinline)
void clean(byte* data, uint len)
{
    for (uint i = 0; i < len; i++)
    {
        // prevent link to the "memset"
        data[i] |= 0x00;
    }
}
