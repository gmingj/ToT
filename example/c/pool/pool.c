#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/queue.h>

struct elm_st {
    SLIST_ENTRY(elm_st) le;
    int value;
};

SLIST_HEAD(head_st, elm_st) lh;

void create_pool(int min, int max)
{
    int i;
    struct elm_st *elm;

    SLIST_INIT(&lh);

    for (i = min; i < max + 1; i++) {
        elm = (struct elm_st *)malloc(sizeof(struct elm_st));
        assert(elm != NULL);

        elm->value = i;
        SLIST_INSERT_HEAD(&lh, elm, le);
    }
    
}

void destroy_pool(void)
{
    struct elm_st *elm;

    SLIST_FOREACH(elm, &lh, le) {
        SLIST_REMOVE(&lh, elm, elm_st, le);
        free(elm);
    }
}

int alloc_id(void)
{
    int value;
    struct elm_st *elm;

    if (SLIST_EMPTY(&lh))
        return -1;

    elm = SLIST_FIRST(&lh);
    value = elm->value;

    SLIST_REMOVE_HEAD(&lh, le); 
    free(elm);

    return value;
}

int free_id(int value)
{
    struct elm_st *elm = (struct elm_st *)malloc(sizeof(struct elm_st));
    assert(elm != NULL);

    elm->value = value;
    SLIST_INSERT_HEAD(&lh, elm, le);

    return 0;
}

void traverse_pool(void (*callback)(struct elm_st *elm))
{
    struct elm_st *elm;
    SLIST_FOREACH(elm, &lh, le) {
        callback(elm);
    }
}

void print(struct elm_st *elm)
{
    printf("%d ", elm->value);
}

int main(int argc, char *argv[])
{
    int i;

    create_pool(1, 10);

    printf("begin: ");
    traverse_pool(print);
    printf("\n");

    printf("alloc: ");
    for (i = 0; i < 5; i++) {
        printf("%d ", alloc_id());
    }
    printf("\n");

    printf("after alloc: ");
    traverse_pool(print);
    printf("\n");

    for (i = 10; i < 6; i--)
        free_id(i);

    printf("after free: ");
    traverse_pool(print);
    printf("\n");

    return 0;
}
