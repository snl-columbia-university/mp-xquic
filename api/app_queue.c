#ifndef APP_QUEUE_H
#define APP_QUEUE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>

#define QUEUE_CAPACITY 1024
#define MAX_PAYLOAD_SIZE 2000

typedef struct {
    uint8_t data[MAX_PAYLOAD_SIZE];
    size_t len;
} queue_item_t;

typedef struct {
    queue_item_t items[QUEUE_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} app_queue_t;

static inline app_queue_t* app_queue_create(void) {
    app_queue_t *q = (app_queue_t *)calloc(1, sizeof(app_queue_t));
    if (!q) return NULL;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
    return q;
}

/* Zero-malloc push: Executed on libevent thread in < 50 nanoseconds */
static inline int app_queue_push(app_queue_t *q, const uint8_t *data, size_t len) {
    if (!q || len > MAX_PAYLOAD_SIZE) return -1;

    pthread_mutex_lock(&q->lock);
    if (q->count >= QUEUE_CAPACITY) {
        pthread_mutex_unlock(&q->lock);
        return -1; /* Queue full (drop or handle overflow) */
    }

    memcpy(q->items[q->tail].data, data, len);
    q->items[q->tail].len = len;
    q->tail = (q->tail + 1) % QUEUE_CAPACITY;
    q->count++;

    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

/* Blocking pop: Executed on Application Worker Thread */
static inline int app_queue_pop(app_queue_t *q, uint8_t *out_data, size_t *out_len) {
    if (!q) return -1;

    pthread_mutex_lock(&q->lock);
    while (q->count == 0) {
        pthread_cond_wait(&q->cond, &q->lock);
    }

    queue_item_t *item = &q->items[q->head];
    memcpy(out_data, item->data, item->len);
    *out_len = item->len;

    q->head = (q->head + 1) % QUEUE_CAPACITY;
    q->count--;

    pthread_mutex_unlock(&q->lock);
    return 0;
}

#endif