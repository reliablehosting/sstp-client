/*!
 * @brief This is the sstp-client code
 *
 * @file sstp-client.c
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>


#include "sstp-private.h"
#include "sstp-client.h"

/*! Global context for the sstp-client */
static sstp_client_st client;


static void sstp_client_event_cb(sstp_client_st *client, int ret)
{
    uint8_t *skey;
    uint8_t *rkey;
    size_t   slen;
    size_t   rlen;

    /* Check the result of the event */
    if (SSTP_OKAY != ret)
    {
        sstp_die("Failed to recieve ip-up notify callback", -1);
    }

    /* Get the result */
    ret = sstp_event_mppe_result(client->event, &skey, &slen, &rkey, &rlen);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Failed to obtain the MPPE keys", -1);
    }

    /* Set the MPPE keys */
    sstp_state_mppe_keys(client->state, skey, slen, rkey, rlen);

    /* Tell the state machine to connect */
    ret = sstp_state_accept(client->state);
    if (SSTP_FAIL == ret)
    {
        sstp_die("Negotiation with server failed", -1);
    }
}


static void sstp_client_pppd_cb(sstp_client_st *client, sstp_pppd_event_t ev)
{
    int ret = (-1);

    switch (ev)
    {
    case SSTP_PPP_DOWN:
	log_err("PPPd terminated");
	//sstp_state_disconnect(client->state);
	event_base_loopbreak(client->ev_base);
        break;

    case SSTP_PPP_UP:
        log_info("PPP UP");
        break;

    case SSTP_PPP_AUTH:
    {
        uint8_t skey[16];
        uint8_t rkey[16];

        /* Get the password */
        const char *password = (client->option.have.password) 
                ? client->option.password 
                : NULL;

        /* Get the MPPE keys */
        ret = sstp_chap_mppe_get(sstp_pppd_getchap(client->pppd), password, 
                skey, rkey, 0); 
        if (SSTP_FAIL == ret)
        {
            return;
        }

        /* Set the keys */
        sstp_state_mppe_keys(client->state, skey, 16, rkey, 16);

        /* Tell the state machine to connect */
        ret = sstp_state_accept(client->state);
        if (SSTP_FAIL == ret)
        {
            sstp_die("Negotiation with server failed", -1);
        }

        break;
    }

    default:
        
        break;
    }

    return;
}


/*!
 * @brief Called when the state machine transitions
 */
static void sstp_client_state_cb(sstp_client_st *client, sstp_state_t event)
{
    int ret = 0;

    switch (event)
    {
    case SSTP_CALL_CONNECT:

        /* Create the PPP context */
        ret = sstp_pppd_create(&client->pppd, client->ev_base, client->stream, 
                (sstp_pppd_fn) sstp_client_pppd_cb, client);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not initalize PPP daemon", -1);
        }

        /* Start the pppd daemon */
        ret = sstp_pppd_start(client->pppd, &client->option, 
                sstp_event_sockname(client->event));
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not start PPP daemon", -1);
        }

        /* Set the forwarder function */
        sstp_state_set_forward(client->state, (sstp_state_forward_fn) 
                sstp_pppd_send, client->pppd);

        log_info("Started PPP Link Negotiation");
        break;
    
    case SSTP_CALL_ESTABLISHED:
        log_info("Connection Established");
        break;

    case SSTP_CALL_ABORT:
    default:
        sstp_die("Connection was aborted, %s", -1, 
                sstp_state_reason(client->state));
        break;
    }
}


/*! 
 * @brief Called upon HTTP handshake complete w/result
 */
static void sstp_client_http_done(sstp_client_st *client, int status)
{
    int opts = SSTP_VERIFY_NONE;

    if (SSTP_OKAY != status)
    {
        sstp_die("HTTP handshake with server failed", -1);
    }

    /* Free the handshake data */
    sstp_http_free(client->http);
    client->http = NULL;

    /* Set verify options */
    opts = SSTP_VERIFY_NAME;
    if (client->option.have.ca_cert ||
        client->option.have.ca_path)
    {
        opts = SSTP_VERIFY_CERT;
    }

    /* Verify the server certificate */
    status = sstp_verify_cert(client->stream, client->host.name, opts);
    if (SSTP_OKAY != status)
    {
        sstp_die("Verification of server certificate failed", -2);
    }

    /* Now we need to start the state-machine */
    status = sstp_state_create(&client->state, client->stream, (sstp_state_change_fn)
            sstp_client_state_cb, client, SSTP_MODE_CLIENT);
    if (SSTP_OKAY != status)
    {
        sstp_die("Could not create state machine", -1);
    }

    /* Kick off the state machine */
    status = sstp_state_start(client->state);
    if (SSTP_FAIL == status)
    {
        sstp_die("Could not start the state machine", -1);
    }
}


/*!
 * @brief Called upon connect complete w/result
 */
static void sstp_client_connected(sstp_stream_st *stream, sstp_buff_st *buf, 
        sstp_client_st *client, status_t status)
{
    int ret  = 0;

    if (SSTP_CONNECTED != status)
    {
        sstp_die("Could not complete connect to the client", -1);
    }

    /* Success! */
    log_info("Connected to %s", client->host.name);

    /* Create the HTTP handshake context */
    ret = sstp_http_create(&client->http, client->host.name, (sstp_http_done_fn) 
            sstp_client_http_done, client, SSTP_MODE_CLIENT);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not configure HTTP handshake with server", -1);
    }

    /* Perform the HTTP handshake with server */
    ret = sstp_http_handshake(client->http, client->stream);
    if (SSTP_FAIL == ret)
    {
        sstp_die("Could not perform HTTP handshake with server", -1);
    }

    return;
}


/*!
 * @brief Connect to the server
 */
static status_t sstp_client_connect(sstp_client_st *client, 
        struct sockaddr *addr, int alen)
{
    status_t ret;

    /* Create the I/O streams */
    ret = sstp_stream_create(&client->stream, client->ev_base, client->ssl_ctx);
    if (SSTP_OKAY != ret)
    {
        log_err("Could not setup SSL streams");
        goto done;
    }

    /* Have the stream connect */
    ret = sstp_stream_connect(client->stream, addr, alen, (sstp_complete_fn) 
            sstp_client_connected, client, 10);
    if (SSTP_INPROG != ret && 
        SSTP_OKAY   != ret)
    {
        log_err("Could not connect to the server");
        goto done;
    }

    /* Success! */
    ret = SSTP_OKAY;

done:

    return ret;
}


/*!
 * @brief Perform the global SSL initializers
 */
static status_t sstp_init_ssl(sstp_client_st *client, sstp_option_st *opt)
{
    int retval = SSTP_FAIL;
    int status = 0;

    /* Initialize the OpenSSL library */
    status = SSL_library_init();
    if (status != 1)
    {
        log_err("Could not initialize SSL");
        goto done;
    }

    /* Load all error strings */
    SSL_load_error_strings();

    /* Create a new crypto context */
    client->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (client->ssl_ctx == NULL)
    {
        log_err("Could not get SSL crypto context");
        goto done;
    }

    /* Configure the crypto options, eliminate SSLv2 */
    status = SSL_CTX_set_options(client->ssl_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
    if (status == -1)
    {
        log_err("Could not set SSL options");
        goto done;
    }

    /* Configure the CA-Certificate or Directory */
    if (opt->have.ca_cert || opt->have.ca_path)
    {
        /* Look for certificates in the default certificate path */
        status = SSL_CTX_load_verify_locations(client->ssl_ctx, 
                (opt->have.ca_cert) ? opt->ca_cert : NULL,
                (opt->have.ca_path) ? opt->ca_path : NULL);
        if (status != 1)
        {
            log_err("Could not set default verify location");
            goto done;
        }
    }

    SSL_CTX_set_verify_depth(client->ssl_ctx, 1);

    /*! Success */
    retval = SSTP_OKAY;

done:
    
    return (retval);
}


/*!
 * @brief Lookup the server name
 */
static status_t sstp_client_lookup(sstp_client_st *client)
{
    status_t status    = SSTP_FAIL;
    sstp_peer_st *peer = &client->host;
    sstp_url_st  *url  = client->url;
    addrinfo_st *list  = NULL;
    addrinfo_st hints;
    const char *service = NULL;
    int ret;

    /* Provide the hints to getaddrinfo */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_protocol   = 0;
    hints.ai_flags      = AI_PASSIVE     |
                          AI_CANONNAME;
    
    /* Get the service string */
    service = (url->port) 
        ? url->port
        : url->protocol;

    /* Resolve the server address */
    ret = getaddrinfo(url->site, service, &hints, &list);
    if (ret != 0 || !list)
    {
        log_err("Could not resolve host: %s, %s (%d)",
                url->site, gai_strerror(ret), ret);
        goto done;
    }

    /* Save the results for later */
    strncpy(peer->name, list->ai_canonname, sizeof(peer->name));
    memcpy(&peer->addr, list->ai_addr, sizeof(peer->addr));
    peer->alen = list->ai_addrlen;

    /* Success! */
    status = SSTP_OKAY;

done:
    
    if (list)
    {
        freeaddrinfo(list);
    }

    return status;
}


/*!
 * @brief Initialize the sstp-client 
 */
static status_t sstp_client_init(sstp_client_st *client, sstp_option_st *opts)
{
    int retval = SSTP_FAIL;
    int status = 0;

    /* Initialize the event library */
    client->ev_base = event_base_new();
    if (!client->ev_base)
    {
        log_err("Could not initialize event base");
        goto done;
    }

    /* Initialize the SSL context, cert store, etc */
    status = sstp_init_ssl(client, opts);
    if (SSTP_OKAY != status)
    {
        log_err("Could not initialize secure socket layer");
        goto done;
    }
    
    /* Convert the server to URL componentized string */
    status = sstp_url_split(&client->url, opts->server);
    if (SSTP_OKAY != status)
    {
        log_err("Could not parse server argument");
        goto done;
    }

    /* Keep a copy of the options */
    memcpy(&client->option, opts, sizeof(client->option));

    /* Success! */
    retval = SSTP_OKAY;

done:
    
    return retval;
}


/*!
 * @brief Free any associated resources with the client
 */
static void sstp_client_free(sstp_client_st *client)
{
    /* Destory the HTTPS stream */
    if (client->stream)
    {
        sstp_stream_destroy(client->stream);
        client->stream = NULL;
    }

    /* Shutdown the SSL context */
    if (client->ssl_ctx)
    {
        SSL_CTX_free(client->ssl_ctx);
        client->ssl_ctx = NULL;
    }

    /* Close the PPPD layer */
    if (client->pppd)
    {
        sstp_pppd_free(client->pppd);
        client->pppd = NULL;
    }

    /* Close the IPC */
    if (client->event)
    {
        sstp_event_free(client->event);
        client->event = NULL;
    }

    /* Free the event base */
    event_base_free(client->ev_base);
}


void sstp_signal_cb(int signal)
{
    log_err("Terminating on %s (%d)", 
            strsignal(signal), signal);

    event_base_loopbreak(client.ev_base);
}


status_t sstp_signal_init(void)
{
    status_t status = SSTP_FAIL;
    struct sigaction act;
    int ret = -1;

    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    act.sa_handler = sstp_signal_cb;

    /* Handle Ctrl+C on keyboard */
    ret = sigaction(SIGINT, &act, NULL);
    if (ret)
    {   
        goto done;
    }

    ret = sigaction(SIGHUP, &act, NULL);
    if (ret)
    {   
        goto done;
    }

    /* Handle program termination */
    ret = sigaction(SIGTERM, &act, NULL);
    if (ret)
    {
        goto done;
    }

    /* Success */
    status = SSTP_OKAY;

done:
    
    return status;
}


/*!
 * @brief The main application entry-point
 */
int main(int argc, char *argv[])
{
    sstp_option_st option;
    int ret = 0;

    /* Reset the memory */
    memset(&client, 0, sizeof(client));

    /* Perform initialization */
    ret = sstp_log_init_argv(&argc, argv);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not initialize logging", -1);
    }

    ret = sstp_signal_init();
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not initialize signal handling", -1);
    }
    
    /* Parse the arguments */
    ret = sstp_parse_argv(&option, argc, argv);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not parse input arguments", -1);
    }

#ifndef HAVE_PPP_PLUGIN
    /* In non-plugin mode, username and password must be specified */
    if (!option.have.password || !option.have.user)
    {
        sstp_die("The password and username must be specified", -1);
    }
#endif /* #ifndef HAVE_PPP_PLUGIN */

    /* Initialize the client */
    ret = sstp_client_init(&client, &option);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not initialize the client", -1);
    }

    /* Create the event notification callback */
    ret = sstp_event_create(&client.event, &client.option, client.ev_base,
        (sstp_event_fn) sstp_client_event_cb, &client);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not setup notification", -1);
    }

    /* Perform DNS lookup of the server */
    ret = sstp_client_lookup(&client);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not lookup server `%s'", -1, client.host.name);
    }
    
    /* Connect to the server */
    ret = sstp_client_connect(&client, &client.host.addr, 
            client.host.alen);
    if (SSTP_FAIL == ret)
    {
        sstp_die("Could not connect to `%s'", -1, client.host.name);
    }
    
    /* Wait for the connect to finish and then continue */
    ret = event_base_dispatch(client.ev_base);
    if (ret != 0)
    {
        sstp_die("The event loop terminated unsuccessfully", -1);
    }

    /* Record the session info for the curious peer */
    if (client.pppd)
    {
        sstp_session_st detail;
        char buf1[32];
        char buf2[32];

        /* Try to signal stop first */
        sstp_pppd_stop(client.pppd);

        sstp_pppd_session_details(client.pppd, &detail);
        log_info("SSTP session was established for %s",
                sstp_norm_time(detail.established, buf1, sizeof(buf1)));
        log_info("Received %s, sent %s", 
                sstp_norm_data(detail.rx_bytes, buf1, sizeof(buf1)),
                sstp_norm_data(detail.tx_bytes, buf2, sizeof(buf2)));
    }

    /* Release allocated resources */
    sstp_client_free(&client);
    return EXIT_SUCCESS;
}
