#ifndef APP_QUEUE_H
#define APP_QUEUE_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define QUEUE_CAPACITY 4096
#define MAX_PAYLOAD_SIZE 2000

typedef struct {
    uint8_t data[MAX_PAYLOAD_SIZE];
    size_t len;
    double recv_time_ms; /* Timestamp recorded at network arrival */
} queue_item_t;

typedef struct {
    queue_item_t items[QUEUE_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int running;
} app_queue_t;

static inline app_queue_t* app_queue_create(void) {
    app_queue_t *q = (app_queue_t *)calloc(1, sizeof(app_queue_t));
    if (!q) return NULL;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
    q->running = 1;
    return q;
}

static inline int app_queue_push(app_queue_t *q, const uint8_t *data, size_t len, double recv_time_ms) {
    if (!q || !q->running || len > MAX_PAYLOAD_SIZE) return -1;

    pthread_mutex_lock(&q->lock);
    if (q->count >= QUEUE_CAPACITY) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }

    memcpy(q->items[q->tail].data, data, len);
    q->items[q->tail].len = len;
    q->items[q->tail].recv_time_ms = recv_time_ms;
    q->tail = (q->tail + 1) % QUEUE_CAPACITY;
    q->count++;

    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

static inline int app_queue_pop(app_queue_t *q, uint8_t *out_data, size_t *out_len, double *out_recv_time_ms) {
    if (!q) return -1;

    pthread_mutex_lock(&q->lock);
    while (q->count == 0 && q->running) {
        pthread_cond_wait(&q->cond, &q->lock);
    }

    if (q->count == 0 && !q->running) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }

    queue_item_t *item = &q->items[q->head];
    memcpy(out_data, item->data, item->len);
    *out_len = item->len;
    if (out_recv_time_ms) *out_recv_time_ms = item->recv_time_ms;

    q->head = (q->head + 1) % QUEUE_CAPACITY;
    q->count--;

    pthread_mutex_unlock(&q->lock);
    return 0;
}

static inline void app_queue_destroy(app_queue_t *q) {
    if (!q) return;
    pthread_mutex_lock(&q->lock);
    q->running = 0;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);

    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->cond);
    free(q);
}

#endif