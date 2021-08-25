#ifndef _OR_QUEUE_H
#define _OR_QUEUE_H

typedef struct ITEM {
    int key;
    void * statellite;
} item_t;

typedef struct QUEUE
{
    int head;
    int tail;
    int count;
    int size;
    item_t** array;
} queue_t;

int queue_init(queue_t * Q, int size);
int queue_resize(queue_t * Q, int size);
int queue_free(queue_t * Q);
int queue_empty(queue_t * Q);
int queue_enqueue(queue_t * Q, item_t* item);
int queue_dequeue(queue_t * Q, item_t** item);
void queue_info(queue_t * Q);

#endif

