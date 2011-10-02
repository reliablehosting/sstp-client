/*!
 * @brief SSL Handling Routines
 *
 * @file sstp-ssl.c
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
 *
 * @TODO:
 *   - Implement functions to get 
 *     -> sstp_stream_recv_http(), this receives a http response
 *     -> sstp_stream_recv_sstp(), this receives a sstp packet
 *   
 *   - We need to make sure we can send *and* receive sstp packets at 
 *     the same time, e.g. while sending; we may need to receive.
 *
 *   - Handle certificate verification, need to get the 
 *     certificate digest for use in the communication
 *     -> sstp_stream_certhash();   // Get certificate hash
 *     -> sstp_stream_getsess();    // Get SSL session info
 *
 *   - Set the SSL_MODE_AUTO_RETRY
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>

#include "sstp-private.h"


/*!
 * @brief A asynchronous send or recv channel object
 */
typedef struct
{
    /*< The socket */
    int sock;

    /*< The event structure */
    event_st *ev_event;

    /*< Timeout if any */
    timeval_st tout;

    /*< Associated buffer with this channel */
    sstp_buff_st *buf;

    /*< Complete callback function */
    sstp_complete_fn complete;

    /*< Argument to pass back the complete function */
    void *arg;
    
} sstp_channel_st;


/*! 
 * @brief The ssl client context
 */
struct sstp_stream
{
    /*< The socket */
    int sock;

    /*< Last activity seen on socket */
    time_t last;

    /*< The SSL connection context */
    SSL *ssl;

    /*< The SSL context structure */
    SSL_CTX *ssl_ctx;

    /*< The length check function */
    sstp_recv_fn recv_cb;

    /*< Channel for receive operation */
    sstp_channel_st recv;

    /*< Channel for send operation */
    sstp_channel_st send;

    /*< The event base */
    event_base_st *ev_base;
};


/*!
 * @brief Continue the send operation
 */
static void sstp_send_cont(int sock, short event, sstp_stream_st *ctx)
{
    sstp_channel_st *ch = &ctx->send;
    int ret = 0;

    // TODO: HANDLE TIMEOUT

    /* Retry the send operation, better luck this time */
    ret = sstp_stream_send(ctx, ch->buf, ch->complete, ch->arg, 
            ch->tout.tv_sec);
    switch (ret)
    {
    case SSTP_FAIL:
    case SSTP_OKAY:

        /* Notify the caller of the status */
        ch->complete(ctx, ch->buf, ch->arg, ret);
        break;

    case SSTP_INPROG:

        /* This state is already handled */
        break;
    }
}


static void sstp_recv_cont(int sock, short event, sstp_stream_st *ctx)
{
    sstp_channel_st *ch = &ctx->recv;
    int ret = 0;

    /* Handle Timeout */
    if (EV_TIMEOUT & event)
    {
        ch->complete(ctx, ch->buf, ch->arg, SSTP_TIMEOUT);
        return;
    }

    /* Try to receive data */
    ret = (ctx->recv_cb)(ctx, ch->buf, ch->complete, ch->arg, 
            ch->tout.tv_sec);
    switch (ret)
    {
    case SSTP_FAIL:
    case SSTP_OKAY:
        
        /* Notify the caller of the status */
        ch->complete(ctx, ch->buf, ch->arg, ret);
        break;

    case SSTP_INPROG:
        
        /* This state is already handled */
        break;
    }
}


static void sstp_channel_setup(sstp_stream_st *ctx, sstp_channel_st *ch, 
    sstp_buff_st *buf, int timeout, sstp_complete_fn complete, void *arg)
{
    ch->buf         = buf;
    ch->complete    = complete;
    ch->arg         = arg;
    ch->tout.tv_sec = timeout;

    /* libevent cannot re-use same socket */
    if (ch->sock <= 0)
    {
        ch->sock = dup(ctx->sock); 
    }

    return;
}


status_t sstp_get_cert_hash(sstp_stream_st *ctx, int proto, 
    unsigned char *hash, int hlen)
{
    status_t status    = SSTP_FAIL;
    const EVP_MD *type = (SSTP_PROTO_HASH_SHA256 & proto)
        ? EVP_sha256()
        : EVP_sha1() ;
    X509 *peer = NULL;
    int ret = 0;

    /* Reset the hash output */
    memset(hash, 0, hlen);

    /* Get the peer certificate */
    peer = SSL_get_peer_certificate(ctx->ssl);
    if (!peer)
    {
        log_err("Failed to get peer certificate");
        goto done;
    }

    /* Get the digest */
    ret = X509_digest(peer, type, hash, (unsigned int*) &hlen);
    if (ret != 1)
    {
        log_err("Failed to get certificate hash");
        goto done;
    }
    
    /* Success! */
    status = SSTP_OKAY;

done:

    return (status);
}


status_t sstp_verify_cert(sstp_stream_st *ctx, const char *host, int opts)
{
    status_t status = SSTP_FAIL;
    X509_NAME *name = NULL;
    X509 *peer = NULL;
    char result[256];
    
    /* Get the peer certificate */
    peer = SSL_get_peer_certificate(ctx->ssl);
    if (!peer)
    {
        log_err("Could not get peer certificate");
        goto done;
    }

    /* Verify the certificate chain */
    if (SSTP_VERIFY_CERT & opts)
    {
        int ret = SSL_get_verify_result(ctx->ssl);
        if (X509_V_OK != ret)
        { 
            log_err("SSL certificate verification failed: %s (%d)", 
                    X509_verify_cert_error_string(ret), ret);
            goto done;
        }
    }

    /* Verify the name of the server */
    if (SSTP_VERIFY_NAME & opts)
    {
        /* Extract the subject name field */
        name = X509_get_subject_name(peer);
        if (!name)
        {
            log_err("Could not get subject name");
            goto done;
        }

        /* Get the common name of the certificate */
        X509_NAME_get_text_by_NID(name, NID_commonName, 
                result, sizeof(result));
        if (strcasecmp(host, result))
        {
            log_err("The certificate did not match the host: %s", host);
            goto done;
        }
    }

    /* Success */
    status = SSTP_OKAY;

done:

    return status;
}

status_t sstp_last_activity(sstp_stream_st *stream, int seconds)
{
    if (difftime(time(NULL), stream->last) > seconds)
    {
        return SSTP_FAIL;
    }

    return SSTP_OKAY;
}


/* 
 * Stubbed function for now...
 */
status_t sstp_stream_recv_http(sstp_stream_st *ctx, sstp_buff_st *buf, 
        sstp_complete_fn complete, void *arg, int timeout)
{
    return SSTP_NOTIMPL;
}


status_t sstp_stream_recv(sstp_stream_st *ctx, sstp_buff_st *buf, 
        sstp_complete_fn complete, void *arg, int timeout)
{
    sstp_channel_st *ch = &ctx->recv;
    status_t status = SSTP_FAIL;
    short event = 0;
    int ret = 0;

    /* Save the arguments in case of callback */
    sstp_channel_setup(ctx, ch, buf, timeout, complete, arg);
    ctx->recv_cb = sstp_stream_recv;

    /* Setup the timeout */
    if (timeout > 0)
    {
        event |= EV_TIMEOUT;
    }

    /* Activity Timer */
    ctx->last = time(NULL);

    /* Try to read from the SSL socket */
    ret = SSL_read(ctx->ssl, buf->data + buf->off, buf->max - buf->off);
    switch (SSL_get_error(ctx->ssl, ret))
    {
    case SSL_ERROR_NONE:
        buf->off += ret;
        status = SSTP_OKAY;
        break;

    case SSL_ERROR_WANT_READ:
        event |= EV_READ;
        event_set(ch->ev_event, ch->sock, event,
                (event_fn) sstp_recv_cont, ctx);
        status = SSTP_INPROG;
        goto done;

    case SSL_ERROR_WANT_WRITE:
        event |= EV_WRITE;
        event_set(ch->ev_event, ch->sock, event,
                (event_fn) sstp_recv_cont, ctx);
        status = SSTP_INPROG;
        goto done;
    
    default:
        log_err("Unrecoverable SSL error %d", ret);
        goto done;
    }

done:

    /* No need to add event... */
    if (SSTP_INPROG != status)
    {
        return status;
    }

    /* Update the event base */
    event_base_set(ctx->ev_base, ch->ev_event);

    /* Add the event */
    ret = event_add(ch->ev_event, &ch->tout);
    if (ret != 0)
    {
        log_err("Could not add new event");
        status = SSTP_FAIL;
    }

    return status;
}


status_t sstp_stream_recv_sstp(sstp_stream_st *ctx, sstp_buff_st *buf, 
        sstp_complete_fn complete, void *arg, int timeout)
{
    sstp_channel_st *ch= &ctx->recv;
    status_t status = SSTP_FAIL;
    short event = 0;
    int ret = 0;

    /* Save the arguments in case of callback */
    sstp_channel_setup(ctx, ch, buf, timeout, complete, arg);

    /* Setup the timeout */
    if (timeout > 0)
    {
        event |= EV_TIMEOUT;
    }

    /* Activity Timer */
    ctx->last = time(NULL);

    do
    {
        /* Try to the header first, then the entire packet */
        buf->len = (buf->len >= 4)
            ? sstp_pkt_len(buf)
            : 4 ;

        /* Try to read from the SSL socket */
        ret = SSL_read(ctx->ssl, buf->data + buf->off, 
                buf->len - buf->off);
        switch (SSL_get_error(ctx->ssl, ret))
        {
        case SSL_ERROR_NONE:
            buf->off += ret;
            break;

        case SSL_ERROR_WANT_READ:
            event |= EV_READ;
            event_set(ch->ev_event, ch->sock, event,
                    (event_fn) sstp_recv_cont, ctx);
            status = SSTP_INPROG;
            goto done;

        case SSL_ERROR_WANT_WRITE:
            event |= EV_WRITE;
            event_set(ch->ev_event, ch->sock, event,
                    (event_fn) sstp_recv_cont, ctx);
            status = SSTP_INPROG;
            goto done;
        
        default:
            log_err("Unrecoverable SSL error");
            goto done;
        }

    } while (buf->off < sstp_pkt_len(buf));

    /* Success */
    status = SSTP_OKAY;

done:

    /* No need to add event... */
    if (SSTP_INPROG != status)
    {
        return status;
    }

    /* Update the event base */
    event_base_set(ctx->ev_base, ch->ev_event);

    /* Add the event */
    ret = event_add(ch->ev_event, &ch->tout);
    if (ret != 0)
    {
        log_err("Could not add new event");
        status = SSTP_FAIL;
    }

    return status;
}


void sstp_stream_setrecv(struct sstp_stream *ctx, sstp_recv_fn recv_cb,
    sstp_buff_st *buf, sstp_complete_fn complete, void *arg, int timeout)
{
    short event = EV_READ;
    
    /* Setup the channel */
    sstp_channel_st *ch = &ctx->recv;
    sstp_channel_setup(ctx, ch, buf, timeout, complete, arg);
    ctx->recv_cb = recv_cb;

    /* We need to reset the buffer */
    sstp_buff_reset(buf);

    /* Configure timeout? */
    if (timeout > 0)
    {
        event |= EV_TIMEOUT;
    }

    /* Setup a receive event */
    ch->ev_event = event_new(ctx->ev_base, ch->sock, event, (event_fn)
            sstp_recv_cont, ctx);
    event_base_set(ctx->ev_base, ch->ev_event);

    /* Add the event */
    event_add(ch->ev_event, (timeout > 0) ? &ch->tout : NULL);
}


#if 0

/*!
 * @brief Receive a HTTP response
 * 
 * @par Note:
 *   The intention is to build a reliable receiver of HTTP requests, let's
 *   tackle that later; reading the full chunk will work for now...
 * 
 *   In general, if no 'Content-Length' attribute is specified, but the 
 *   'Transfer-Encoding is specified to 'Chunked' then just after the 
 *   header -- a blank line, and then a number in hexdecimal. We can
 *   parse this number to find out how many more bytes there is to
 *   read from the stream. If 'Content-Length' is specified, then this
 *   will be the number of bytes contained within the body.
 * 
 */
status_t sstp_stream_recv_http(sstp_stream_st *stream, sstp_buff_st *buf, 
    sstp_complete_fn complete, void *arg)
{
    int ret  =  0;
    int code =  0;
    int attr = 10;
    status_t status = SSTP_FAIL;

    http_header_st array[10];
    http_header_st *entry = NULL;
    sstp_buff_st *buf = fsm->buf;

    /* Try to read the most we can */
    buf->len = buf->max;
    buf->off = 0;

    /* Try to receive a blob */
    ret = sstp_stream_recv(fsm->stream, fsm->buf,
            sstp_stream_http_complete, fsm);
    switch (ret)
    {
    case SSTP_FAIL:
        // Error out
        goto done;

    case SSTP_INPROG:
        // Additional handling here?
        goto done;
    
    case SSTP_OKAY:
        break;
    }

    /*
     * Call function to determine length of HTTP Response given the amount
     * of data that we have received. We might need to do multiple recv()
     * before all the data of the HTTP stream is consumed.
     * 
     * We don't have to read the data per-byte (block increment will do).
     * In the case we do have more data to read, add a read-event and 
     * wait for select() to signal read again now set with the correct 
     * length of the buffer.
     */

    /* Get the HTTP headers */
    ret = sstp_http_get(fsm->buf, &code, &attr, array);
    if (SSTP_OKAY != ret)
    {
        log_err("Could not parse the HTTP headers");
        goto done;
    }

    /* If there is any additional data available ... */
    entry = sstp_http_get_header("Content-Length", attr, array);
    if (entry)
    {
        buf->len = strtoul(entry->value, NULL, 10);
        buf->off = 0;

        ret = sstp_stream_recv(fsm->stream, fsm->buf,
                sstp_recv_hello_complete, fsm);
        if (SSTP_OKAY != ret)
        {
            goto done;
        }

        buf->data[buf->len] = '\0';
        log_info("Received: %d\n%s\n", buf->len, buf->data);
    }
    
    /* Validate the response */
    status = SSTP_OKAY;

done:

    return status;
}
#endif


status_t sstp_stream_send(sstp_stream_st *stream, sstp_buff_st *buf,
    sstp_complete_fn complete, void *arg, int timeout)
{
    sstp_channel_st *ch = &stream->send;
    status_t status = SSTP_FAIL;
    int ret = 0;

    /* Save the arguments in case of callback */
    sstp_channel_setup(stream, ch, buf, timeout, complete, arg);
    stream->last = time(NULL);

    do
    {
        /* Try SSL write to the socket */
        ret = SSL_write(stream->ssl, buf->data + buf->off, 
                buf->len - buf->off);
        switch (SSL_get_error(stream->ssl, ret))
        {
        case SSL_ERROR_NONE:
            buf->off += ret;
            break;

        case SSL_ERROR_WANT_READ:
            event_set(ch->ev_event, ch->sock, EV_READ | EV_TIMEOUT,
                    (event_fn) sstp_send_cont, stream);
            status = SSTP_INPROG;
            goto done;
        
        case SSL_ERROR_WANT_WRITE:
            event_set(ch->ev_event, ch->sock, EV_WRITE | EV_TIMEOUT,
                    (event_fn) sstp_send_cont, stream);
            status = SSTP_INPROG;
            goto done;

        default:
            log_err("Unrecoverable socket error");
            goto done;
        }

    } while (buf->off < buf->len);

    /* Success */
    status = SSTP_OKAY;

done:

    /* Don't wait for the complete callback */ 
    if (SSTP_INPROG != status)
    {
        return status;
    }
    
    /* Update the event base */
    event_base_set(stream->ev_base, ch->ev_event);

    /* Add the event */
    ret = event_add(ch->ev_event, &ch->tout);
    if (ret != 0)
    {
        log_err("Could not add new event");
        status = SSTP_FAIL;
    }

    return (status);

}


static status_t sstp_stream_setup(sstp_stream_st *stream)
{
    /* Associate the streams */
    stream->ssl = SSL_new(stream->ssl_ctx);
    if (stream->ssl == NULL)
    {
        log_err("Could not create SSL session", -1);
        goto done;
    }

    /* Associate a socket with the connection */
    if (SSL_set_fd(stream->ssl, stream->sock) < 0)
    {   
        log_err("Could not set SSL socket");
        goto done;
    }   

    /* Set Client Mode (connect) */
    SSL_set_connect_state(stream->ssl);

    /* Success */
    return SSTP_OKAY;

done:

    if (stream->ssl != NULL)
    {   
        SSL_free(stream->ssl);
        stream->ssl = NULL;
    }   

    return SSTP_FAIL;
}


static void sstp_connect_complete(int sock, short event, 
        sstp_stream_st *stream)
{
    sstp_channel_st *ch = &stream->send;
    status_t status = SSTP_FAIL;
    int ret = -1;

    /* In case connect timed out */
    if (EV_TIMEOUT & event)
    {
        log_err("Connect timed out");
        goto done;
    }

    /* Configure the SSL context */
    ret = sstp_stream_setup(stream);
    if (SSTP_OKAY != ret)
    {
        log_err("Could not configure SSL socket");
        goto done;
    }

    /* Success! */
    status = SSTP_CONNECTED;

done:

    /* Propagate the information */
    ch->complete(stream, NULL, ch->arg, status);
}


status_t sstp_stream_connect(sstp_stream_st *stream, struct sockaddr *addr,
        int alen, sstp_complete_fn complete, void *arg, int timeout)
{
    int ret = (-1);

    /* Create the socket */
    stream->sock = socket(PF_INET, SOCK_STREAM, 0);
    if (0 > stream->sock)
    {          
        log_err("Could not create socket");
        goto done;
    }

    /* Set socket non-blocking mode */
    ret = sstp_set_nonbl(stream->sock, 1);
    if (SSTP_OKAY != ret)
    {
        log_err("Unable to set non-blocking operation");
        goto done;
    }   
    
    /* Set send buffer size */
    ret = sstp_set_sndbuf(stream->sock, 32768);
    if (SSTP_OKAY != ret)      
    {                                              
        log_warn("Unable to set send buffer size", errno);
    }

    /* Connect to the server (non-blocking) */
    ret = connect(stream->sock, addr, alen);
    if (ret == -1)
    {
        sstp_channel_st *ch = &stream->send;

        /* If we are not blocking b/c of connection in progress */
        if (errno != EINPROGRESS)
        {
            log_err("Connection failed (%d)", errno);
            goto done;
        }

        /* Setup the send channel */
        sstp_channel_setup(stream, ch, NULL, timeout, complete, arg);

        /* Setup the callback */
        ch->ev_event = event_new(stream->ev_base, ch->sock, EV_WRITE | EV_TIMEOUT,
                (event_fn) sstp_connect_complete, stream);

        /* Add event to event-loop */
        ret = event_add(ch->ev_event, &ch->tout);
        if (ret != 0)
        {
            log_err("Could not add new event");
            goto done;
        }
        
        return SSTP_INPROG;
    }

    /* Success */
    return SSTP_OKAY;

done:

    /* Cleanup */
    if (stream->sock >= 0)
    {
        close(stream->sock);
    }
    
    return SSTP_FAIL;
}


status_t sstp_stream_destroy(sstp_stream_st *stream)
{
    status_t retval = SSTP_FAIL;
    int ret = -1;
    
    /* Get the current socket */
    if (stream->sock <= 0)
    {
        log_debug("No socket associated");
        goto done;
    }

    /* Set blocking mode */
    ret = sstp_set_nonbl(stream->sock, 0);
    if (SSTP_OKAY != ret)
    {
        log_warn("Unable to set blocking mode socket");
        goto done;
    }

    /* Shutdown the server */
    SSL_shutdown(stream->ssl);

    /* Free resources */
    SSL_free(stream->ssl);
    stream->ssl = NULL;

    /* Free the send event */
    if (stream->send.ev_event)
    {
        event_del(stream->send.ev_event);
        event_free(stream->send.ev_event);
    }

    /* Free the receive event */
    if (stream->recv.ev_event)
    {
        event_del(stream->recv.ev_event);
        event_free(stream->recv.ev_event);
    }

    /* Free the stream */
    free(stream);

    /* Success */
    retval = SSTP_OKAY;

done:

    return (retval);
}


status_t sstp_stream_create(sstp_stream_st **stream, event_base_st *base, 
        SSL_CTX *ssl)
{
    /* Create a new stream */
    sstp_stream_st *stream_= calloc(1, sizeof(sstp_stream_st));
    if (!stream_)
    {
        return SSTP_FAIL;
    }

    /* Associate stream with ssl context */
    stream_->ev_base = base;
    stream_->ssl_ctx = ssl;
    *stream = stream_;

    /* Success */
    return SSTP_OKAY;
}

