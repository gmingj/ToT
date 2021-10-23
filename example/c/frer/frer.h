#ifndef FRER_H
#define FRER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/time.h>

/**
 * @brief Frer descriptor.
 * 
 */
typedef struct frer frer_t;

/**
 * @brief Callback function for frer_loop.
 * 
 */
typedef void (*frer_callback)(void *user, const void *pkt, int len);

/**
 * @brief Obtain a handle to process packets on the talker-end.
 * 
 * @param dev1 One of the name of the outbound interface of the redundant path.
 * @param dev2 One of the name of the outbound interface of the redundant path.
 * @return frer_t* Return a frer_t * on success and NULL on failure.
 */
frer_t *frer_open_talker(const char *dev1, const char *dev2);

/**
 * @brief Transmit a message to listener-end through redundant paths.
 * 
 * @param p Handle of the talker instance.
 * @param buf Buffer containing the message.
 * @param size Size of the buffer.
 * @return int Return 0 on success and -1 on failure.
 */
int frer_tx(frer_t *p, const void *buf, int size);

/**
 * @brief Close the files associated with p and deallocates resources on the talker-end.
 * 
 * @param p Handle of the talker instance.
 */
void frer_close_talker(frer_t *p);

/**
 * @brief Obtain a handle to process packets on listener-end.
 * 
 * @param dev1 One of the name of the inbound interface of the redundant path.
 * @param dev2 One of the name of the inbound interface of the redundant path.
 * @return frer_t* Return a frer_t * on success and NULL on failure.
 */
frer_t *frer_open_listener(const char *dev1, const char *dev2);

/**
 * @brief Process packets from a listener instance until cnt packets are processed.
 * 
 * @param p Handle of the listener instance.
 * @param cnt Maximum number of packets to process.
 * @param cb Callback handler function.
 * @param user User argument.
 * @return int Return 0 on success and -1 on failure.
 */
int frer_rx_loop(frer_t *p, int cnt, frer_callback cb, void *user);

/**
 * @brief Close the files associated with p and deallocates resources on the listener-end.
 * 
 * @param p Handle of the listener instance.
 */
void frer_close_listener(frer_t *p);

/**
 * @brief Return a pointer to a string that describes the error code passed in the argument errnum.
 * 
 * @param errnum Return code of a series of frer functions.
 * @return char* Return 'Success' if no error.
 */
char *frer_strerror(int errnum);

#ifdef __cplusplus
}
#endif

#endif /* FRER_H */
