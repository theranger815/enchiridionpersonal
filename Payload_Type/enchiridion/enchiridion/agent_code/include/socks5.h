#ifndef SOCKS5_H
#define SOCKS5_H

#include "cJSON.h"

void  socksInit(void);
void  socksTeardown(void);
void  socksFlush(void);
void  socksProcessInbound(cJSON *socks_array);
cJSON *socksPollOutbound(void);

#endif /* SOCKS5_H */
