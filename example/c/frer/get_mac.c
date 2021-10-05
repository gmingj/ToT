#include <stdio.h>
#include <string.h>
#include <linux/if_ether.h>


int get_mac_address(char *dev, unsigned char *dest, unsigned char *source)
{
    unsigned char dmac[ETH_HLEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    unsigned char smac[ETH_HLEN] = {0x09, 0x08, 0x07, 0x06, 0x05, 0x04};

    memcpy(dest, dmac, ETH_HLEN);
    memcpy(source, smac, ETH_HLEN);

    return 0;
}

char *hexdump(const unsigned char *buffer, int len)
{
    int i = 0, j = 0;
    static char str[BUFSIZ];

    if (len > BUFSIZ/3)
        return "";

    memset(str, '\0', BUFSIZ);
    for (; i < len; i++) {
        sprintf(&str[j], " %02X", buffer[i]);
        j += 3;
    }
    sprintf(&str[j], " ");

    return str;
}

