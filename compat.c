/*
 * Compatibility routines for older rsync protocol versions.
 *
 * Copyright (C) Andrew Tridgell 1996
 * Copyright (C) Paul Mackerras 1996
 * Copyright (C) 2004-2007 Wayne Davison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "rsync.h"

int remote_protocol = 0;
int file_extra_cnt = 0; /* count of file-list extras that everyone gets */
int inc_recurse = 0;

extern int verbose;
extern int am_server;
extern int am_sender;
extern int inplace;
extern int recurse;
extern int fuzzy_basis;
extern int read_batch;
extern int max_delete;
extern int delay_updates;
extern int checksum_seed;
extern int basis_dir_cnt;
extern int prune_empty_dirs;
extern int protocol_version;
extern int preserve_uid;
extern int preserve_gid;
extern int preserve_hard_links;
extern int need_messages_from_generator;
extern int delete_mode, delete_before, delete_during, delete_after;
extern char *dest_option;

void setup_protocol(int f_out,int f_in)
{
	if (am_sender)
		file_extra_cnt += PTR_EXTRA_LEN;
	else
		file_extra_cnt++;
	if (preserve_uid)
		preserve_uid = ++file_extra_cnt;
	if (preserve_gid)
		preserve_gid = ++file_extra_cnt;

	if (remote_protocol == 0) {
		if (!read_batch)
			write_int(f_out, protocol_version);
		remote_protocol = read_int(f_in);
		if (protocol_version > remote_protocol)
			protocol_version = remote_protocol;
	}
	if (read_batch && remote_protocol > protocol_version) {
	        rprintf(FERROR, "The protocol version in the batch file is too new (%d > %d).\n",
			remote_protocol, protocol_version);
		exit_cleanup(RERR_PROTOCOL);
	}

	if (verbose > 3) {
		rprintf(FINFO, "(%s) Protocol versions: remote=%d, negotiated=%d\n",
			am_server? "Server" : "Client", remote_protocol, protocol_version);
	}
	if (remote_protocol < MIN_PROTOCOL_VERSION
	 || remote_protocol > MAX_PROTOCOL_VERSION) {
		rprintf(FERROR,"protocol version mismatch -- is your shell clean?\n");
		rprintf(FERROR,"(see the rsync man page for an explanation)\n");
		exit_cleanup(RERR_PROTOCOL);
	}
	if (remote_protocol < OLD_PROTOCOL_VERSION) {
		rprintf(FINFO,"%s is very old version of rsync, upgrade recommended.\n",
			am_server? "Client" : "Server");
	}
	if (protocol_version < MIN_PROTOCOL_VERSION) {
		rprintf(FERROR, "--protocol must be at least %d on the %s.\n",
			MIN_PROTOCOL_VERSION, am_server? "Server" : "Client");
		exit_cleanup(RERR_PROTOCOL);
	}
	if (protocol_version > PROTOCOL_VERSION) {
		rprintf(FERROR, "--protocol must be no more than %d on the %s.\n",
			PROTOCOL_VERSION, am_server? "Server" : "Client");
		exit_cleanup(RERR_PROTOCOL);
	}

	if (protocol_version < 30) {
		if (max_delete == 0 && am_sender) {
			rprintf(FERROR,
			    "--max-delete=0 requires protocol 30 or higher"
			    " (negotiated %d).\n",
			    protocol_version);
			exit_cleanup(RERR_PROTOCOL);
		}
	}

	if (delete_mode && !(delete_before+delete_during+delete_after)) {
		if (protocol_version < 30)
			delete_before = 1;
		else
			delete_during = 1;
	}

	if (protocol_version < 29) {
		if (fuzzy_basis) {
			rprintf(FERROR,
			    "--fuzzy requires protocol 29 or higher"
			    " (negotiated %d).\n",
			    protocol_version);
			exit_cleanup(RERR_PROTOCOL);
		}

		if (basis_dir_cnt && inplace) {
			rprintf(FERROR,
			    "%s with --inplace requires protocol 29 or higher"
			    " (negotiated %d).\n",
			    dest_option, protocol_version);
			exit_cleanup(RERR_PROTOCOL);
		}

		if (basis_dir_cnt > 1) {
			rprintf(FERROR,
			    "Using more than one %s option requires protocol"
			    " 29 or higher (negotiated %d).\n",
			    dest_option, protocol_version);
			exit_cleanup(RERR_PROTOCOL);
		}

		if (prune_empty_dirs) {
			rprintf(FERROR,
			    "--prune-empty-dirs requires protocol 29 or higher"
			    " (negotiated %d).\n",
			    protocol_version);
			exit_cleanup(RERR_PROTOCOL);
		}
	} else if (protocol_version >= 30) {
		if (recurse && !preserve_hard_links && !delete_before
		 && !delete_after && !delay_updates && !prune_empty_dirs)
			inc_recurse = 1;
		need_messages_from_generator = 1;
	}

	if (am_server) {
		if (!checksum_seed)
			checksum_seed = time(NULL);
		write_int(f_out, checksum_seed);
	} else {
		checksum_seed = read_int(f_in);
	}
}
