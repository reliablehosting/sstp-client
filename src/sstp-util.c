/*!
 * @brief Utility Functions
 *
 * @file sstp-util.c
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 *
 * @par License:
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "sstp-private.h"


status_t sstp_set_nonbl(int sock, int state)
{
    int ret  = -1;
    int flag = fcntl(sock, F_GETFL);

    flag = (state == 1) 
        ? (flag | O_NONBLOCK)
        : (flag & ~O_NONBLOCK);

    ret = fcntl(sock, F_SETFL, flag);
    if (ret != 0)
    {
        return SSTP_FAIL;
    }

    return SSTP_OKAY;
}


char *sstp_get_guid(char *buf, int len)
{
    uint32_t data1, data4;
    uint16_t data2, data3;
    unsigned int seed;
    int ret;

    seed = time(NULL) | getpid();
    srand (seed);

    data1 = (rand() + 1);
    data2 = (rand() + 1);
    data3 = (rand() + 1);
    data4 = (rand() + 1);

    /* Create the GUID string */
    ret = snprintf(buf, len, "{%.4X-%.2X-%.2X-%.4X}", data1, data2, 
            data3, data4);
    if (ret <= 0 || ret > len)
    {
        return NULL;
    }

    return buf;    
}


status_t sstp_set_sndbuf(int sock, int size)
{
    int ret = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    if (ret != 0)
    {
        return SSTP_FAIL;
    }

    return SSTP_OKAY;
}


status_t sstp_url_split(sstp_url_st **url, const char *path)
{
    char *ptr = NULL;
    char *ptr1 = NULL;

    /* Allocate url context */
    sstp_url_st *ctx = calloc(1, sizeof(sstp_url_st));
    if (!ctx)
    {
        goto errout;
    }
    
    /* Copy to working buffer */
    ctx->ptr = strdup(path);
    ptr = ctx->ptr;
    
    /* Look for the protocol string */
    ptr1 = strstr(ptr, "://");
    if (ptr1 != NULL)
    {
        ctx->protocol = ptr;
        *ptr1 = '\0';
        ptr1  += 3;
        ptr    = ptr1;
    }

    /* Set the site pointer */
    ctx->site = ptr;

    /* Look for the optional port component */
    ptr1 = strchr(ptr, ':');
    if (ptr1 != NULL)
    {
        /* Get the site */
        *ptr1++ = '\0';
        ptr     = ptr1;
        ctx->port = ptr1;
    }

    /* Look for the path component */
    ptr1 = strchr(ptr, '/');
    if (ptr1 != NULL)
    {
        *ptr1++ = '\0';
        ctx->path = ptr1;
    }

    /* Either must be specified */
    if (!ctx->protocol && !ctx->port)
    {
        ctx->port = "443";
    }

    /* Success */
    *url = ctx;
    return SSTP_OKAY;

errout:
    
    if (ctx)
    {
        sstp_url_free(ctx);
    }

    return SSTP_FAIL;
}


void sstp_url_free(sstp_url_st *url)
{
    if (!url)
    {
        return;
    }

    if (url->ptr)
    {
        free(url->ptr);
        url->ptr = NULL;
    }

    free(url);
}


const char *sstp_norm_data(unsigned long long count, char *buf, int len)
{
    float b = count;
    char v [] = { 'K', 'M', 'G', 'T' };
    int i = 0;

    if (count < 1024) 
    {
        snprintf(buf, len, "%llu bytes", count);
        return buf;
    }

    while (b > 1024)
    {
        b /= 1024;
        i++;
    }

    snprintf(buf, len, "%.02f %cb", b, v[i]);
    return buf;
}


/*!
 * @brief Normilize into hour, min or sec.
 */
const char *sstp_norm_time(unsigned long t, char *buf, int len)
{
    if (t > 3600)
    {
        snprintf(buf, len, "%.02f hour(s)", (float)t/3600);
        return buf;
    }

    if (t > 60)
    {
        snprintf(buf, len, "%.02f minute(s)", (float)t/60);
        return buf;
    }

    snprintf(buf, len, "%lu seconds", t);
    return buf;
}


#if 0
int main(int argc, char *argv[])
{
    sstp_url_st *url;

    sstp_split_url(&url, argv[1]);

    printf("protocol: %s\n", url->protocol);
    printf("site:     %s\n", url->site);
    printf("port:     %s\n", url->port);
    printf("path:     %s\n", url->path);
}

#endif
