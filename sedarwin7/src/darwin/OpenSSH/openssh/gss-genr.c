/*	$OpenBSD: gss-genr.c,v 1.3 2003/11/21 11:57:03 djm Exp $	*/

/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef GSSAPI

#include "ssh.h"
#include "xmalloc.h"
#include "bufaux.h"
#include "buffer.h"
#include "packet.h"
#include "compat.h"
#include <openssl/evp.h>
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "compat.h"
#include "monitor_wrap.h"

#include <netdb.h>
#include "ssh2.h"

#include "ssh-gss.h"

typedef struct {
	char *encoded;
	gss_OID oid;
} ssh_gss_kex_mapping;
	
static ssh_gss_kex_mapping *gss_enc2oid;

/* Return a list of the gss-group1-sha1-x mechanisms supported by this
 * program.
 *
 * On the client side, we don't need to worry about whether we 'know'
 * about the mechanism or not - we assume that any mechanism that we've been
 * linked against is suitable for inclusion.
 *
 * XXX - We might want to make this configurable in the future, so as to
 * XXX - allow the user control over which mechanisms to use.
 */
 
char * 
ssh_gssapi_client_mechanisms(const char *host) {
	gss_OID_set 	supported;
	OM_uint32	min_status;
	Buffer		buf;
	int 		i = 0;
	char 		*mechs;
	char		*encoded;
	int		enclen;
	char		digest[EVP_MAX_MD_SIZE];
	char		deroid[2];
	const EVP_MD	*evp_md = EVP_md5();
	EVP_MD_CTX	md;
	int 		oidpos=0;
	
	
	gss_indicate_mechs(&min_status,&supported);
		if (datafellows & SSH_BUG_GSSAPI_BER) {
		gss_enc2oid=xmalloc(sizeof(ssh_gss_kex_mapping)
					*((supported->count*2)+1));
	} else {
		gss_enc2oid=xmalloc(sizeof(ssh_gss_kex_mapping)
					*(supported->count+1));
		}
	
	buffer_init(&buf);


	for (i=0;i<supported->count;i++) {

		gss_enc2oid[oidpos].encoded=NULL;
		
		if (supported->elements[i].length<128 &&
		    ssh_gssapi_check_mechanism(&(supported->elements[i]),host)) {

			/* Earlier versions of this code interpreted the
			 * spec incorrectly with regard to OID encoding. They
			 * also mis-encoded the krb5 OID. The following
			 * _temporary_ code interfaces with these broken
			 * servers */

			if (datafellows & SSH_BUG_GSSAPI_BER) {
				char *bodge=NULL;
				gss_OID_desc krb5oid={9, "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02"};
				gss_OID_desc gsioid={9, "\x2B\x06\x01\x04\x01\x9B\x50\x01\x01"};
				
				if (supported->elements[i].length==krb5oid.length &&
				    memcmp(supported->elements[i].elements,
				    	   krb5oid.elements, krb5oid.length)==0) {
					bodge="Se3H81ismmOC3OE+FwYCiQ==";
				}
				
				if (supported->elements[i].length==gsioid.length &&
				    memcmp(supported->elements[i].elements,
				    	   gsioid.elements, gsioid.length)==0) {
					bodge="N3+k7/4wGxHyuP8Yxi4RhA==";
				}

				if (bodge) {				
					if (oidpos!=0) {
						buffer_put_char(&buf,',');
					}
				
					buffer_append(&buf, KEX_GSS_SHA1, sizeof(KEX_GSS_SHA1)-1);
					buffer_append(&buf, bodge, strlen(bodge));

					gss_enc2oid[oidpos].oid=&(supported->elements[i]);
					gss_enc2oid[oidpos].encoded=bodge;
			
					oidpos++;
				}
			}
			
			/* Add the required DER encoding octets and MD5 hash */
			deroid[0]=0x06; /* Object Identifier */
			deroid[1]=supported->elements[i].length;

			EVP_DigestInit(&md, evp_md);
			EVP_DigestUpdate(&md,deroid,2);
			EVP_DigestUpdate(&md,
					 supported->elements[i].elements,
					 supported->elements[i].length);
			EVP_DigestFinal(&md, digest, NULL);
			
			/* Base64 encode it */
			encoded=xmalloc(EVP_MD_size(evp_md)*2);
			enclen=__b64_ntop(digest, EVP_MD_size(evp_md),
				          encoded,EVP_MD_size(evp_md)*2);
			if (oidpos!=0) {
				buffer_put_char(&buf,',');
			}	
			buffer_append(&buf, KEX_GSS_SHA1, sizeof(KEX_GSS_SHA1)-1);
			buffer_append(&buf, encoded, enclen);

			debug("Mechanism encoded as %s",encoded);

			gss_enc2oid[oidpos].oid=&(supported->elements[i]);
			gss_enc2oid[oidpos].encoded=encoded;			
			oidpos++;
		}
	}
	gss_enc2oid[oidpos].oid=NULL;
	gss_enc2oid[oidpos].encoded=NULL;
	
	buffer_put_char(&buf,'\0');
	
	mechs=xmalloc(buffer_len(&buf));
	buffer_get(&buf,mechs,buffer_len(&buf));
	buffer_free(&buf);
	if (strlen(mechs)==0)
		return(NULL);
	else
		return(mechs);
}

gss_OID
ssh_gssapi_client_id_kex(Gssctxt *ctx, char *name) {
	int i=0;
	
	if (strncmp(name, KEX_GSS_SHA1, sizeof(KEX_GSS_SHA1)-1) !=0) {
		return(NULL);
	}
	
	name+=sizeof(KEX_GSS_SHA1)-1; /* Move to the start of the ID string */
	
	while (gss_enc2oid[i].encoded!=NULL &&
	       	strcmp(name,gss_enc2oid[i].encoded)!=0) {
	      	i++;
	}
	
	if (gss_enc2oid[i].oid!=NULL) {
		ssh_gssapi_set_oid(ctx,gss_enc2oid[i].oid);
	}

	return gss_enc2oid[i].oid;
}

extern u_char *session_id2;
extern u_int session_id2_len;

/* Check that the OID in a data stream matches that in the context */
int
ssh_gssapi_check_oid(Gssctxt *ctx, void *data, size_t len)
{
	return (ctx != NULL && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->length == len &&
	    memcmp(ctx->oid->elements, data, len) == 0);
}

/* Set the contexts OID from a data stream */
void
ssh_gssapi_set_oid_data(Gssctxt *ctx, void *data, size_t len)
{
	if (ctx->oid != GSS_C_NO_OID) {
		xfree(ctx->oid->elements);
		xfree(ctx->oid);
	}
	ctx->oid = xmalloc(sizeof(gss_OID_desc));
	ctx->oid->length = len;
	ctx->oid->elements = xmalloc(len);
	memcpy(ctx->oid->elements, data, len);
}

/* Set the contexts OID */
void
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_data(ctx, oid->elements, oid->length);
}

/* All this effort to report an error ... */
void
ssh_gssapi_error(Gssctxt *ctxt)
{
	debug("%s", ssh_gssapi_last_error(ctxt, NULL, NULL));
}

char *
ssh_gssapi_last_error(Gssctxt *ctxt,
		      OM_uint32 *major_status, OM_uint32 *minor_status)
{
	OM_uint32 lmin;
	gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
	OM_uint32 ctx;
	Buffer b;
	char *ret;

	buffer_init(&b);

	if (major_status != NULL)
		*major_status = ctxt->major;
	if (minor_status != NULL)
		*minor_status = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	do {
		gss_display_status(&lmin, ctxt->major,
		    GSS_C_GSS_CODE, GSS_C_NULL_OID, &ctx, &msg);

		buffer_append(&b, msg.value, msg.length);
		buffer_put_char(&b, '\n');

		gss_release_buffer(&lmin, &msg);
	} while (ctx != 0);

	/* The mechanism specific error */
	do {
		gss_display_status(&lmin, ctxt->minor,
		    GSS_C_MECH_CODE, GSS_C_NULL_OID, &ctx, &msg);

		buffer_append(&b, msg.value, msg.length);
		buffer_put_char(&b, '\n');

		gss_release_buffer(&lmin, &msg);
	} while (ctx != 0);

	buffer_put_char(&b, '\0');
	ret = xmalloc(buffer_len(&b));
	buffer_get(&b, ret, buffer_len(&b));
	buffer_free(&b);
	return (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
void
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xmalloc(sizeof (Gssctxt));
	(*ctx)->major = 0;
	(*ctx)->minor = 0;
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
void
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	if ((*ctx) == NULL)
		return;
	if ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_BUFFER);
	if ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	if ((*ctx)->oid != GSS_C_NO_OID) {
		xfree((*ctx)->oid->elements);
		xfree((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	if ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	if ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	if ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	xfree(*ctx);
	*ctx = NULL;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, int deleg_creds, gss_buffer_desc *recv_tok,
    gss_buffer_desc* send_tok, OM_uint32 *flags)
{
	int deleg_flag = 0;

	if (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    GSS_C_NO_CREDENTIAL, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, NULL, recv_tok, NULL, send_tok, flags, NULL);

	if (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	return (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, const char *host)
{
	gss_buffer_desc gssbuf;

	gssbuf.length = sizeof("host@") + strlen(host);
	gssbuf.value = xmalloc(gssbuf.length);
	snprintf(gssbuf.value, gssbuf.length, "host@%s", host);

	if ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	xfree(gssbuf.value);
	return (ctx->major);
}

/* Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */

/* Returns a GSSAPI error code */
OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx)
{
	OM_uint32 status;
	char lname[MAXHOSTNAMELEN];
	gss_OID_set oidset;

	gss_create_empty_oid_set(&status, &oidset);
	gss_add_oid_set_member(&status, ctx->oid, &oidset);

	if (gethostname(lname, MAXHOSTNAMELEN))
		return (-1);

	if (GSS_ERROR(ssh_gssapi_import_name(ctx, lname)))
		return (ctx->major);

	if ((ctx->major = gss_acquire_cred(&ctx->minor,
	    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds, NULL, NULL)))
		ssh_gssapi_error(ctx);

	gss_release_oid_set(&status, &oidset);
	return (ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_t buffer, gss_buffer_t hash)
{
	if ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, buffer, hash)))
		ssh_gssapi_error(ctx);

	return (ctx->major);
}

void
ssh_gssapi_buildmic(Buffer *b, const char *user, const char *service,
    const char *context)
{
	buffer_init(b);
	buffer_put_string(b, session_id2, session_id2_len);
	buffer_put_char(b, SSH2_MSG_USERAUTH_REQUEST);
	buffer_put_cstring(b, user);
	buffer_put_cstring(b, service);
	buffer_put_cstring(b, context);
}


int
ssh_gssapi_check_mechanism(gss_OID oid, const char *host)
{
	Gssctxt * ctx = NULL;
	gss_buffer_desc token;
	OM_uint32 major,minor;
	
	ssh_gssapi_build_ctx(&ctx);
	ssh_gssapi_set_oid(ctx,oid);
	ssh_gssapi_import_name(ctx, (char *) host);
	major=ssh_gssapi_init_ctx(ctx,0, GSS_C_NO_BUFFER, &token, NULL);
	gss_release_buffer(&minor,&token);
	ssh_gssapi_delete_ctx(&ctx);
	return(!GSS_ERROR(major));
}
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid) {
	if (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	return (ssh_gssapi_acquire_cred(*ctx));
}

#endif /* GSSAPI */
