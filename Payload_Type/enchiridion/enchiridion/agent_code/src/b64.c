#include "b64.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char encoding_table[64] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
    'q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9','+','/'
};

static const int mod_table[3] = {0, 2, 1};

// Compile-time table: avoids heap allocation and thread-safety issues.
static const unsigned char decoding_table[256] = {
    ['+'] = 62, ['/'] = 63,
    ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55, ['4'] = 56,
    ['5'] = 57, ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61,
    ['A'] =  0, ['B'] =  1, ['C'] =  2, ['D'] =  3, ['E'] =  4,
    ['F'] =  5, ['G'] =  6, ['H'] =  7, ['I'] =  8, ['J'] =  9,
    ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13, ['O'] = 14,
    ['P'] = 15, ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19,
    ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23, ['Y'] = 24,
    ['Z'] = 25,
    ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30,
    ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
    ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40,
    ['p'] = 41, ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45,
    ['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49, ['y'] = 50,
    ['z'] = 51,
};

// Returns a null-terminated base64 string; *output_length is the length
// excluding the null terminator. Caller frees the result.
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length + 1);
    if (!encoded_data)
        return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >>  6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >>  0) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    encoded_data[*output_length] = '\0';
    return encoded_data;
}

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length) {
    if (input_length % 4 != 0)
        return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=')
        (*output_length)--;
    if (data[input_length - 2] == '=')
        (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (!decoded_data)
        return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        unsigned char c0 = (unsigned char)data[i++];
        unsigned char c1 = (unsigned char)data[i++];
        unsigned char c2 = (unsigned char)data[i++];
        unsigned char c3 = (unsigned char)data[i++];

        uint32_t sextet_a = c0 == '=' ? 0 : decoding_table[c0];
        uint32_t sextet_b = c1 == '=' ? 0 : decoding_table[c1];
        uint32_t sextet_c = c2 == '=' ? 0 : decoding_table[c2];
        uint32_t sextet_d = c3 == '=' ? 0 : decoding_table[c3];

        uint32_t triple = (sextet_a << 18) | (sextet_b << 12) |
                          (sextet_c <<  6) | (sextet_d <<  0);

        if (j < *output_length)
            decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length)
            decoded_data[j++] = (triple >>  8) & 0xFF;
        if (j < *output_length)
            decoded_data[j++] = (triple >>  0) & 0xFF;
    }

    return decoded_data;
}
