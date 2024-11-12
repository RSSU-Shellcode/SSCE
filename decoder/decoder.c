#pragma warning(disable: 4255)
#pragma warning(disable: 4711)

typedef unsigned int  uint;
typedef unsigned char uint8;
typedef unsigned long uint32;
typedef uint8 byte;

void decrypt(byte* data, uint dataLen, byte* key, uint keyLen);
void clean(byte* data, uint len);

static uint32 xorShift32(uint32 seed);
static byte   ror(byte value, uint8 bits);
static byte   rol(byte value, uint8 bits);

// prevent incorrect optimization of the number of parameters
#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain() {
    byte sc0[]  = { 's', 'c' };
    byte key0[] = { 'k', 'e', 'y', '0'};
    decrypt(sc0, 2, key0, 4);
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
    uint32 ctr  = *(uint32*)(key+4);
    uint32 last = *(uint32*)(key+0);
    uint keyIdx = last % 32;
    for (uint i = 0; i < dataLen; i++)
    {
        byte b = *data;
        b = rol(b, (uint8)(last % 8));
        b -= (byte)(ctr ^ last);
        b ^= key[keyIdx];
        b = ror(b, (uint8)(last % 8));
        b ^= (byte)(last);
        *data = b;
        // update key index
        keyIdx++;
        if (keyIdx >= keyLen)
        {
            keyIdx = 0;
        }
        ctr++;
        last = xorShift32(last);
        // update data address
        data++;
    }
}

static uint32 xorShift32(uint32 seed)
{
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}

static byte ror(byte value, uint8 bits)
{
    return value >> bits | value << (8 - bits);
}

static byte rol(byte value, uint8 bits)
{
    return value << bits | value >> (8 - bits);
}

// prevent link to the internel "memset"
__declspec(noinline)
void clean(byte* data, uint len)
{
    for (uint i = 0; i < len; i++)
    {
        data[i] ^= data[i]+1;
    }
}
