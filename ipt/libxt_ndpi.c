/* 
 * libxt_ndpi.c
 * Copyright (C) 2010-2012 G. Elian Gidoni
 *               2012 Ed Wildgoose
 *               2014 Humberto Jucá <betolj@gmail.com>
 * 
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <xtables.h>

#include <linux/version.h>

#include "xt_ndpi.h"

static char *prot_long_str[] = { NDPI_PROTOCOL_LONG_STRING };
static char *prot_short_str[] = { NDPI_PROTOCOL_SHORT_STRING };


static void 
ndpi_mt4_save(const void *entry, const struct xt_entry_match *match)
{
	const struct xt_ndpi_mtinfo *info = (const void *)match->data;
        int i;

        for (i = 1; i <= NDPI_LAST_NFPROTO; i++){
                if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0){
                        printf(" --%s ", prot_short_str[i]);
                }
        }
}


static void 
ndpi_mt4_print(const void *entry, const struct xt_entry_match *match,
                  int numeric)
{
	const struct xt_ndpi_mtinfo *info = (const void *)match->data;
	int i;

        for (i = 1; i <= NDPI_LAST_NFPROTO; i++){
                if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0){
                        printf("protocol %s ", prot_long_str[i]);
                }
        }
}


static int 
ndpi_mt4_parse(int c, char **argv, int invert, unsigned int *flags,
                  const void *entry, struct xt_entry_match **match)
{
	struct xt_ndpi_mtinfo *info = (void *)(*match)->data;

        if (c >= 0 && c <= NDPI_LAST_NFPROTO) {
                NDPI_ADD_PROTOCOL_TO_BITMASK(info->flags, c);
                *flags = 1;
                return true;
        }
        *flags = 0;
	return false;
}

#ifndef xtables_error
#define xtables_error exit_error
#endif

static void
ndpi_mt_check (unsigned int flags)
{
	if (flags == 0){
		xtables_error(PARAMETER_PROBLEM, "xt_ndpi: You need to "
                              "specify at least one protocol");
	}
}


static void
ndpi_mt_help(void)
{
        int i;

	printf("ndpi match options:\n");
        for (i = 1; i <= NDPI_LAST_NFPROTO; i++){
                printf("--%s Match for %s protocol packets.\n",
                       prot_short_str[i], prot_long_str[i]);
        }
}


static void 
ndpi_mt_init (struct xt_entry_match *match)
{
	struct xt_ndpi_mtinfo *info = (void *)match->data;
	/* inet_pton(PF_INET, "192.0.2.137", &info->dst.in); */
}


static struct option ndpi_mt_opts[NDPI_LAST_NFPROTO+1];

static struct xtables_match
ndpi_mt4_reg = {
	.version = XTABLES_VERSION,
	.name = "ndpi",
	.revision = 0,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
	.family = AF_INET,
#else
	.family = NFPROTO_IPV4,
#endif
	.size = XT_ALIGN(sizeof(struct xt_ndpi_mtinfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_ndpi_mtinfo)),
	.help = ndpi_mt_help,
	.init = ndpi_mt_init,
	.parse = ndpi_mt4_parse,
	.final_check = ndpi_mt_check,
	.print = ndpi_mt4_print,
	.save = ndpi_mt4_save,
	.extra_opts = ndpi_mt_opts,
};

void _init(void)
{
        int i;

        for (i = 0; i < NDPI_LAST_NFPROTO; i++){
                ndpi_mt_opts[i].name = prot_short_str[i+1];
                ndpi_mt_opts[i].has_arg = false;
                ndpi_mt_opts[i].val = i+1;
        }
        ndpi_mt_opts[i].name = NULL;
        ndpi_mt_opts[i].flag = NULL;
        ndpi_mt_opts[i].has_arg = 0;
        ndpi_mt_opts[i].val = 0;

	xtables_register_match(&ndpi_mt4_reg);
}
