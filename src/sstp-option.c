/*!
 * @brief Command line parsing for sstp-client
 *
 * @file sstp-options.c
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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "sstp-private.h"


void sstp_die(const char *message, int code, ...)
{
    va_list list;
    char format[SSTP_DFLT_BUFSZ];
    char buff[SSTP_DFLT_BUFSZ];

    /* Make sure we log the message to syslog, etc */
    va_start(list, code);
    vsnprintf(buff, sizeof(buff)-1, message, list);
    va_end(list);
    sstp_log_msg(SSTP_LOG_ERR, __FILE__, __LINE__, "%s", buff); 

    /* Format the error string */
    snprintf(format, sizeof(format)-1, "**Error: %s, (%d)\n", 
            message, code);
    
    /* Format the message */
    va_start(list, code);
    vprintf(format, list);
    va_end(list);

    /* Exit */
    exit(code);
}


void sstp_usage_die(const char *prog, int code, 
    const char *message, ...)
{
    va_list list;
    char format[SSTP_DFLT_BUFSZ+1];
    int ret = (-1);

    printf("%s v%s\n", PACKAGE_NAME, PACKAGE_VERSION);
    printf("Copyright (C) Eivind Naess 2011, All Rights Reserved\n\n");
    printf("License GPLv2+: GNU GPL version 2 or later <http://gnu.org/licenses/gpl.html>\n");
    printf("This is free software: you are free to change and redistribute it.\n");
    printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
    printf("Report Bugs:\n  %s\n\n", PACKAGE_BUGREPORT);


    /* Print the usage text */
    printf("Usage: %s <sstp-options> <hostname> [[--] <pppd-options>]\n", prog);
    printf("   Or: pppd pty \"%s --nolaunchpppd <sstp-options> <hostname>\"\n\n", prog);
    printf("Available sstp options:\n");
    printf("  --ca-cert <cert>         Provide the CA certificate in PEM format\n");
    printf("  --ca-path <path>         Provide the CA certificate path\n");
    printf("  --ipparam <param>        The unique connection id used w/pppd\n");
    printf("  --help                   Display this menu\n");
    printf("  --debug                  Enable debug mode\n");
    printf("  --nolaunchpppd           Don't start pppd, for use with pty option\n");
    printf("  --user                   Username\n");
    printf("  --password               Password\n");
    printf("  --version                Display the version information\n\n");

    /* Additional log usage */
    sstp_log_usage();

    /* Format the message */
    ret  = snprintf(format, SSTP_DFLT_BUFSZ, "**Error: Could not execute `%s', %s (%d)\n",
            prog, message, code);
    if (ret >= sizeof(format))
    {
        format[SSTP_DFLT_BUFSZ] = '\0';
    }

    /* Print the error */
    va_start(list, message);   
    vprintf(format, list);
    va_end(list);


    /* Exit */
    exit(code);
}


/*!
 * @brief Print the version
 */
static void sstp_print_version(const char *prog)
{
    printf("%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
    exit(0);
}


/*!
 * @brief Handle the individual options here
 */
static void sstp_parse_option(sstp_option_st *ctx, int argc, char **argv, int index)
{
    switch (index)
    {
    case 0:
        strncpy(ctx->ca_cert, optarg, sizeof(ctx->ca_cert)-1);
        ctx->have.ca_cert = 1;
        break;

    case 1:
        strncpy(ctx->ca_path, optarg, sizeof(ctx->ca_path)-1);
        ctx->have.ca_path = 1;
        break;

    case 2:
        ctx->enable |= SSTP_OPT_DEBUG;
        break;

    case 3:
        sstp_usage_die(argv[0], 0, "Showing help text");
        break;

    case 4:
        strncpy(ctx->ipparam, optarg, sizeof(ctx->ipparam));
        ctx->have.ipparam = 1;
        break;

    case 5:
        ctx->enable |= SSTP_OPT_NOLAUNCH;
        break;

    case 6: 
        strncpy(ctx->password, optarg, sizeof(ctx->password));
        ctx->have.password = 1;
        break;

    case 7:
        strncpy(ctx->user, optarg, sizeof(ctx->user));
        ctx->have.user = 1;
        break;

    default:
        sstp_usage_die(argv[0], -1, "Unrecognized command line option");
        break;
    }

    return;
}


int sstp_parse_argv(sstp_option_st *ctx, int argc, char **argv)
{
    int option_index = 0;
    static struct option option_long[] = 
    {
        { "ca-cert",        required_argument, NULL,  0  },
        { "ca-path",        required_argument, NULL,  0  },
        { "debug",          no_argument,       NULL,  0  },
        { "help",           no_argument,       NULL,  0  },
        { "ipparam",        required_argument, NULL,  0  },
        { "nolaunchpppd",   no_argument,       NULL,  0  },
        { "password",       required_argument, NULL,  0  },
        { "user",           required_argument, NULL,  0  },
        { "version",        no_argument,       NULL, 'v' },
        { 0, 0, 0, 0 }
    };

    /* Clear the option structure */
    memset(ctx, 0, sizeof(sstp_option_st));

    while (1)
    {
        /* Use getopt to parse the command line */
        char c = getopt_long(argc, argv, "v", option_long, &option_index);
        if (c == -1)
        {
            break;
        }

        switch (c)
        {
        /* Handle the specific option */
        case 0:
            sstp_parse_option(ctx, argc, argv, option_index);
            break;

        case 'v':
            sstp_print_version(argv[0]);
            break;

        /* Invalid option */
        case '?':
            sstp_usage_die(argv[0], -1, "Invalid command line option: `%c'", c);
            break;

        /* Unhandled option */
        default:
            sstp_usage_die(argv[0], -1, "Unrecognized command line option: `%c'", c);
            break;
        }
    }

    /* At least one argument is required */
    if (argc <= optind)
    {
        sstp_usage_die(argv[0], -1, "At least one argument is required");
    }

    /* Copy the server argument */
    strncpy(ctx->server, argv[optind++], sizeof(ctx->server)-1);
    ctx->have.server = 1;

    /* PPPD options to follow */
    ctx->pppdargc = argc - optind;
    ctx->pppdargv = argv + optind;

    return 0;
}


