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

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>


#include "sstp-private.h"
#include "sstp-client.h"
#include <openssl/engine.h>
#include <openssl/ui.h>
#include <openssl/conf.h>
/*! Global context for the sstp-client */
static sstp_client_st client;

typedef void (*sstp_client_cb)(sstp_stream_st*, sstp_buff_st*, sstp_client_st*, status_t);

/*!
 * @brief Called when proxy is connected
 */
static void sstp_client_proxy_connected(sstp_stream_st *stream, sstp_buff_st *buf,
        sstp_client_st *client, status_t status);


static void sstp_client_event_cb(sstp_client_st *client, int ret)
{
    uint8_t *skey;
    uint8_t *rkey;
    size_t   slen;
    size_t   rlen;

    /* Check the result of the event */
    if (SSTP_OKAY != ret)
    {
        sstp_die("Failed to receive ip-up notify callback", -1);
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

        /* Tell the state machine to connect */
        ret = sstp_state_accept(client->state);
        if (SSTP_FAIL == ret)
        {
            sstp_die("Negotiation with server failed", -1);
        }
        break;

    case SSTP_PPP_AUTH:
    {
        uint8_t skey[16];
        uint8_t rkey[16];

        /* Get the MPPE keys */
        ret = sstp_chap_mppe_get(sstp_pppd_getchap(client->pppd), 
                client->option.password, skey, rkey, 0); 
        if (SSTP_FAIL == ret)
        {
            return;
        }

        /* Set the keys */
        sstp_state_mppe_keys(client->state, skey, 16, rkey, 16);
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
            sstp_die("Could not initialize PPP daemon", -1);
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
        
        /* Enter the privilege separation directory */
        if (getuid() == 0)
        {
            ret = sstp_sandbox(client->option.priv_dir, 
                    client->option.priv_user, 
                    client->option.priv_group);
            if (ret != 0) 
            {
                log_warn("Could not enter privilege directory");
            }
        }

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
    if (client->option.ca_cert ||
        client->option.ca_path)
    {
        opts = SSTP_VERIFY_CERT;
    }

    /* Verify the server certificate */
    status = sstp_verify_cert(client->stream, client->option.server, opts);
    if (SSTP_OKAY != status)
    {
        if (!(SSTP_OPT_CERTWARN & client->option.enable))
            sstp_die("Verification of server certificate failed", -2);
        
        log_warn("Server certificated failed verification, ignoring");
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

    /* Set the uuid of the connection if provided */
    if (client->option.uuid)
    {
        sstp_http_setuuid(client->http, client->option.uuid);
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
 * @brief Called on completion of the proxy request
 */
static void sstp_client_proxy_done(sstp_client_st *client, int status)
{
    int ret = 0;

    switch (status)
    {
    /* Proxy asked us to authenticate */
    case SSTP_AUTHENTICATE:
        
        /* Close the connection, re-connect and use the credentials */
        sstp_stream_destroy(client->stream);

        /* Create the SSL I/O streams */
        ret = sstp_stream_create(&client->stream, client->ev_base, 
                client->ssl_ctx);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not create I/O stream", -1);
        }

        /* Proxy asked us to authenticate, but we have no password */
        if (!client->url->password || !client->url->password)
        {
            sstp_die("Proxy asked for credentials, none provided", -1);
        }

        /* Update with username and password */
        sstp_http_setcreds(client->http, client->url->user,
                client->url->password);

        /* Reconnect to the proxy (now with credentials set) */
        ret = sstp_stream_connect(client->stream, &client->host.addr, client->host.alen,
                (sstp_complete_fn) sstp_client_proxy_connected, client, 10);
        break;

    case SSTP_OKAY:

        log_info("Connected to %s via proxy server", 
                client->option.server);

        /* Re-initialize the HTTP context */
        sstp_http_free(client->http);

        /* Create the HTTP handshake context */
        ret = sstp_http_create(&client->http, client->option.server, (sstp_http_done_fn) 
                sstp_client_http_done, client, SSTP_MODE_CLIENT);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not configure HTTP handshake with server", -1);
        }
        
        /* Perform the HTTPS/SSTP handshake */
        ret = sstp_http_handshake(client->http, client->stream);
        if (SSTP_FAIL == ret)
        {
            sstp_die("Could not perform HTTP handshake with server", -1);
        }

        break;

    default:

        sstp_die("Could not connect to proxy server", -1);
        break;
    }

    return;
}


/*!
 * @brief Called when connection to the proxy server is completed
 */
static void sstp_client_proxy_connected(sstp_stream_st *stream, sstp_buff_st *buf,
        sstp_client_st *client, status_t status)
{
    int ret = 0;

    if (SSTP_CONNECTED != status)
    {
        sstp_die("Could not connect to proxy server", -1);
    }

    /* Create the HTTP object if one doesn't already exist */
    if (!client->http) 
    {
        ret = sstp_http_create(&client->http, client->option.server,
            (sstp_http_done_fn) sstp_client_proxy_done, client, SSTP_MODE_CLIENT);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not configure HTTP handshake with server", -1);
        }
    }

    /* Perform the HTTP handshake with server */
    ret = sstp_http_proxy(client->http, client->stream);
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
    sstp_client_cb complete_cb = (client->option.proxy)
            ? sstp_client_proxy_connected
            : sstp_client_connected;
    status_t ret = SSTP_FAIL;

    /* Create the I/O streams */
    ret = sstp_stream_create(&client->stream, client->ev_base, client->ssl_ctx);
    if (SSTP_OKAY != ret)
    {
        log_err("Could not setup SSL streams");
        goto done;
    }

    /* Have the stream connect */
    ret = sstp_stream_connect(client->stream, addr, alen, (sstp_complete_fn) complete_cb, client, 10);
    if (SSTP_INPROG != ret && 
        SSTP_OKAY   != ret)
    {
        log_err("Could not connect to the server, %s (%d)", 
            strerror(errno), errno);
        goto done;
    }

    /* Success! */
    ret = SSTP_OKAY;

done:

    return ret;
}

/*!
 * @brief Password callback for PEM_read_PrivateKey function
 *
 * Mostly borrowed from OpenSSL apps.c file, with significant
 * simplification.
 */

static int password_callback(char *buf, int bufsize, int verify, void
*userdata)
{
    UI *ui = NULL;
	int res = 0;
	const char *prompt_info = NULL;
	const char *password = userdata;
	const char *prompt = "Private key password: ";
	int ui_flags = 0;
	int ok = 0;
	char *buff = NULL;
	if (password) 
	{  
	   /* 
	    * We use userdata ponter to pass password to callback
		* if password is specified as command-line option. 
		* So, if userdata is not NULL, interpret it as pointer to
		* 0-terminatedpassword
		*/
	   res=strlen(password);
	   if (res > bufsize)
	       res = bufsize;
	   memcpy(buf,password, res);
	   return res;
	}
	/* 
	 * Otherwise use openssl UI method to as the passwod
	 */
   ui = UI_new();
   if (!ui) {
		log_err("Error allocating password prompt UI");
		return res;
   }
   ui_flags = UI_INPUT_FLAG_DEFAULT_PWD;
   UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);
   ok = UI_add_input_string(ui,prompt,ui_flags, buf,
  		 SSTP_PW_MIN_LENGTH,bufsize-1);
   if (ok >=0 && verify) 
   {
   	   buff = (char *) OPENSSL_malloc(bufsize);
	   ok = UI_add_verify_string(ui,prompt,ui_flags, buff,
	   	SSTP_PW_MIN_LENGTH, bufsize-1, buf);
   }
   if (ok >= 0) 
      do
	  {
	     ok = UI_process(ui);
	  } 
	  while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));
   
   if (buff)
   {
       OPENSSL_cleanse(buff, (unsigned int) bufsize);
	   OPENSSL_free(buff);
   }
   
   if (ok >= 0)
   {
     res = strlen(buf);
   }
   else 
   {
      OPENSSL_cleanse(buf, (unsigned int) bufsize);
	  res = 0;
   }
   UI_free(ui);
   return res;
}

/*!
 * @brief extracts detailed openssl error information and sends to
 * log_debug
 */ 
static void log_ssl_error(void) 
{
	unsigned long e;
	char buf[128];
	while( (e = ERR_get_error()) ) 
	{
	     log_debug(ERR_error_string(e,buf));
	}
}
/*!
 * @brief Perform the global SSL initializers
 */
static status_t sstp_init_ssl(sstp_client_st *client, sstp_option_st *opt)
{
    int retval = SSTP_FAIL;
    int status = 0;

	ENGINE *e=NULL;
	/* Load default OpenSSL  config file. Typically it does no harm, but can
	 * provice useful things such as engine configuration */
	OPENSSL_config(NULL);
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
		log_ssl_error();
        goto done;
    }

    /* Configure the crypto options, eliminate SSLv2 */
    status = SSL_CTX_set_options(client->ssl_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
    if (status == -1)
    {
        log_err("Could not set SSL options");
		log_ssl_error();
        goto done;
    }

    /* Configure the CA-Certificate or Directory */
    if (opt->ca_cert || opt->ca_path)
    {
        /* Look for certificates in the default certificate path */
        status = SSL_CTX_load_verify_locations(client->ssl_ctx, 
                opt->ca_cert, opt->ca_path);
        if (status != 1)
        {
            log_err("Could not set verify location");
			log_ssl_error();
            goto done;
        }
    }

    SSL_CTX_set_verify_depth(client->ssl_ctx, 1);
	if (opt->engine) 
	{
	/* If engine is specified, try to load it even if it is not used to
	 * store private key
	 */
		e=ENGINE_by_id(opt->engine);
		if (e == NULL) 
		{
			log_err("Couldn't not load engine");
			log_ssl_error();
			goto done;
		}
		if (opt->engine_opts) 
		{
			/* tokenize the options and pass them to ENGINE_ctrl_cmd_string
			* Expect no spaces around commas and equal signs
			*/
			char *opts=opt->engine_opts;
			while (opts) 
			{
				char *p=strchr(opts,',');
				char *current_opt=NULL;
				if (p) {
					current_opt=malloc((p-opts)+1);
					memcpy(current_opt,opts,p-opts);
					opts=p+1;
				}
				else 
				{	
					current_opt=strdup(opts);
					opts=NULL;
				}
				log_debug(current_opt);
				p=strchr(current_opt,'=');
				*(p++)=0;
				if (!ENGINE_ctrl_cmd_string(e, current_opt, p, 0)) 
				{
					const char *msg="Error sending engine command: ";
					p=malloc(strlen(msg)+strlen(current_opt)+1);
					strcpy(p,msg);
					strcat(p,current_opt);
					free(current_opt);
					log_err(p);
					log_ssl_error();
					free(p);
					goto done;
				}
				free(current_opt);
			}		
		}		
		if (!ENGINE_init(e)) 
		{
			log_err("Cannot initialize engine");
			log_ssl_error();
			goto done;
		}
	}
	if (opt->cert) 
	{	
		if (!SSL_CTX_use_certificate_file(client->ssl_ctx, opt->cert,
		          SSL_FILETYPE_PEM)) 
		{
			log_err("Could not load certificate file");
			log_ssl_error();
			goto done;
		}
		
		SSL_CTX_set_default_passwd_cb(client->ssl_ctx,
	 	            password_callback);
		SSL_CTX_set_default_passwd_cb_userdata(client->ssl_ctx,
		            opt->key_pass);

		if (!opt->priv_key) 
		{
			/* Assume that private key in the same file as certificate */
			if (!SSL_CTX_use_PrivateKey_file(client->ssl_ctx,opt->cert,SSL_FILETYPE_PEM))
			{ 
				log_err("Could not load private key from certificate file");
				log_ssl_error();
				goto done;
			}
		} 
		else 
		{
			/* Check if  key is engine-provided */
			if (strncmp("engine:",opt->priv_key,7)==0) 
			{
				EVP_PKEY *key = NULL;
				if (!e) 
				{
					log_err("Engine provided key but no engine loaded");
					goto done;
				}
				key=ENGINE_load_private_key(e,opt->priv_key+7,
				  UI_OpenSSL(),NULL);
				if (!key) 
				{
					log_err("Couldn't load key from the engine");
					log_ssl_error();
					goto done;
				}
				if (!SSL_CTX_use_PrivateKey(client->ssl_ctx,key)) 
				{ 
					log_err("Couldn't use key from engine");
					log_ssl_error();
					EVP_PKEY_free(key);
					goto done;
				}
			} 
			else 
			{
				if (!SSL_CTX_use_PrivateKey_file(client->ssl_ctx,opt->priv_key,
					SSL_FILETYPE_PEM)) 
				{
				   log_err("Could not load private key file");
				   log_ssl_error();
				   goto done;
				}

			}
			if (!SSL_CTX_check_private_key(client->ssl_ctx))
			{	
				log_err("Private key doesn't match certificate");
				log_ssl_error();
				goto done;
			}

		}

	}				
			


	
    /*! Success */
    retval = SSTP_OKAY;

done:
    
    return (retval);
}


/*!
 * @brief Lookup the server name
 */
static status_t sstp_client_lookup(sstp_url_st *uri, sstp_peer_st *peer)
{
    char ipaddr[INET6_ADDRSTRLEN];
    status_t status    = SSTP_FAIL;
    const char *service= NULL;
    addrinfo_st *list  = NULL;
    addrinfo_st hints  = 
    {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = 0,
        .ai_flags    = AI_PASSIVE | AI_CANONNAME,
    };
    int ret;

    /* Get the service string */
    service = (uri->port) 
        ? uri->port
        : uri->schema;

    /* Resolve the server address */
    ret = getaddrinfo(uri->host, service, &hints, &list);
    if (ret != 0 || !list)
    {
        log_err("Could not resolve host: %s, %s (%d)",
                uri->host, gai_strerror(ret), ret);
        goto done;
    }

    /* Save the results for later */
    strncpy(peer->name, (list->ai_canonname) ? : uri->host, sizeof(peer->name));
    memcpy(&peer->addr, list->ai_addr, sizeof(peer->addr));
    peer->alen = list->ai_addrlen;

    log_info("Resolved %s to %s", peer->name, 
        sstp_ipaddr(&peer->addr, ipaddr, sizeof(ipaddr)))

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

    /* Free the route context */
    if (client->route_ctx)
    {
        sstp_route_done(client->route_ctx);
        client->route_ctx = NULL;
    }

    /* Free the options */
    sstp_option_free(&client->option);

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

    /* Setup signal handling */
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

    /* Check if we can access the runtime directory */
    if (access(SSTP_RUNTIME_DIR, F_OK))
    {
        ret = sstp_create_dir(SSTP_RUNTIME_DIR, option.priv_user, 
                option.priv_group, 0755);
        if (ret != 0)
        {
            log_warn("Could not access or create runtime directory");
        }
    }

    /* Create the privilege separation directory */
    if (option.priv_dir && access(option.priv_dir, F_OK))
    {
        ret = sstp_create_dir(option.priv_dir, option.priv_user,
                option.priv_group, 0700);
        if (ret != 0)
        {
            log_warn("Could not access or create privilege separation directory, %s",
                    option.priv_dir);
        }
    }

#ifndef HAVE_PPP_PLUGIN
    /* In non-plugin mode, username and password must be specified */
    if (!option.password || !option.user)
    {
        sstp_die("The username and password must be specified", -1);
    }
#endif /* #ifndef HAVE_PPP_PLUGIN */

    /* Initialize the client */
    ret = sstp_client_init(&client, &option);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not initialize the client", -1);
    }

    /* Create the event notification callback */
    if (!(option.enable & SSTP_OPT_NOPLUGIN))
    {
        ret = sstp_event_create(&client.event, &client.option, client.ev_base,
            (sstp_event_fn) sstp_client_event_cb, &client);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not setup notification", -1);
        }
    }

    /* Connect to the proxy first */
    if (option.proxy)
    {
        /* Parse the Proxy URL */
        ret = sstp_url_parse(&client.url, option.proxy);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not parse the proxy URL", -1);
        }
    }
    else
    {
        ret = sstp_url_parse(&client.url, option.server);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not parse the server URL", -1);
        }
    }

    /* Lookup the URL of the proxy server */
    ret = sstp_client_lookup(client.url, &client.host);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not lookup host: `%s'", -1, client.url->host);
    }

    /* Connect to the server */
    ret = sstp_client_connect(&client, &client.host.addr, 
            client.host.alen);
    if (SSTP_FAIL == ret)
    {
        sstp_die("Could not connect to `%s'", -1, client.host.name);
    }

    /* Add a server route if we are asked to */
    if (option.enable & SSTP_OPT_SAVEROUTE)
    {
        ret = sstp_route_init(&client.route_ctx);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not initialize route module", -1);
        }

        ret = sstp_route_get(client.route_ctx, &client.host.addr,
                &client.route);
        if (ret != 0)
        {
            sstp_die("Could not get server route", -1);
        }

        ret = sstp_route_replace(client.route_ctx, &client.route);
        if (ret != 0)
        {
          sstp_die("Could not replace server route", -1);
        }
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

    /* Remove the server route */
    if (option.enable & SSTP_OPT_SAVEROUTE)
    {
        ret = sstp_route_delete(client.route_ctx, &client.route);
        if (SSTP_OKAY != ret)
        {
            log_warn("Could not remove the server route");
        }
    }

    /* Release allocated resources */
    sstp_client_free(&client);
    return EXIT_SUCCESS;
}
