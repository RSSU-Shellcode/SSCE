#pragma warning(disable: 4255)
#pragma warning(disable: 4711)

#ifdef _WIN64
  typedef unsigned long long uint;
#elif _WIN32
  typedef unsigned long uint;
#endif
typedef unsigned char uint8;
typedef uint8 byte;

void decode(byte* data, uint dataLen, byte* key, uint keyLen);

static uint xorShift(uint seed);
static byte ror(byte value, uint8 bits);
static byte rol(byte value, uint8 bits);

// prevent incorrect optimization of the number of parameters
#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain() {
    byte sc0[]  = { 's', 'c' };
    byte key0[] = { 'k', 'e', 'y', '0'};
    decode(sc0, 2, key0, 4);

    byte sc1[]  = { 's', 'c', '1'};
    byte key1[] = { 'k', 'e', 'y', '1', '2'};
    decode(sc1, 3, key1, 5);
    return (uint)(sc0[0] + sc1[0]);
}

__declspec(noinline)
 void decode(byte* data, uint dataLen, byte* key, uint keyLen)
{
    uint last = *(uint*)(key);
    uint ctr  = *(uint*)(key+sizeof(uint));
    uint keyIdx = last % keyLen;
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
        last = xorShift(last);
        // update data address
        data++;
    }
}

static uint xorShift(uint seed)
{
#ifdef _WIN64
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
#elif _WIN32
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
#endif
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
