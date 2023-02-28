#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "list.h"

struct elm_st {
    SLIST_ENTRY(elm_st) le;
    int i;
};

int main(int argc, char *argv[])
{
    int i = 0;
    struct elm_st *elm;
    SLIST_HEAD(header_st, elm_st) lh;

    SLIST_INIT(&lh);

    for (; i < 10; i++) {
        elm = (struct elm_st *)malloc(sizeof(struct elm_st));
        assert(elm != NULL);

        elm->i = i;
        SLIST_INSERT_HEAD(&lh, elm, le);
    }
    
    SLIST_FOREACH(elm, &lh, le) {
        printf("i = %d\n", elm->i);
    }

    return 0;
}
