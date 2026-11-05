/* Minimal Open Transport constants for macTLS build with GCC */
/* ostls_async.c provides its own type definitions in the #else block */

#ifndef OSTLS_OT_CONSTANTS_H
#define OSTLS_OT_CONSTANTS_H

/* Open Transport event codes */
#define T_GODATA                      0x0100
#define T_GOEXDATA                    0x0200
#define T_LISTEN                      0x0080
#define T_CONNECT                     0x0040
#define T_DISCONNECT                  0x0020
#define T_ERROR                       0x0010
#define T_UDERR                       0x0008
#define T_ORDREL                      0x0004
#define T_DATA                        0x0002
#define T_EXDATA                      0x0001

/* Endpoint states */
#define T_UNBND                       0x0000
#define T_IDLE                        0x0001
#define T_OUTCON                      0x0002
#define T_INCON                       0x0003
#define T_DATAXFER                    0x0004
#define T_OUTREL                      0x0005
#define T_INREL                       0x0006

/* Synchronous call events */
#define kOTSyncIdleEvent              0x20000011

/* Flags */
#define T_MORE                        0x0001
#define T_EXPEDITED                   0x0002

/* Address types */
#define T_IPV4                        0x0002

/* noErr */
#define noErr                         0

#endif /* OSTLS_OT_CONSTANTS_H */

/* OT context provided by application */
extern void *g_ostls_ot_context;
