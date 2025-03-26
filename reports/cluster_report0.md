# Cluster 0 Report

## Function 1
```
Function: verify_chv2 (app_t app,
             gpg_error_t (*pincb)(void*, const char *, char **),
             void *pincb_arg)
{
  int rc;
  char *pinvalue;

  if (app->did_chv2)
    return 0;  /* We already verified CHV2.  */

  rc = verify_a_chv (app, pincb, pincb_arg, 2, 0, &pinvalue);
  if (rc)
    return rc;
  app->did_chv2 = 1;

  if (!app->did_chv1 && !app->force_chv1 && pinvalue)
    {
      /* For convenience we verify CHV1 here too.  We do this only if
         the card is not configured to require a verification before
         each CHV1 controlled operation (force_chv1) and if we are not
         using the pinpad (PINVALUE == NULL). */
      rc = iso7816_verify (app->slot, 0x81, pinvalue, strlen (pinvalue));
      if (gpg_err_code (rc) == GPG_ERR_BAD_PIN)
        rc = gpg_error (GPG_ERR_PIN_NOT_SYNCED);
      if (rc)
        {
          log_error (_("verify CHV%d failed: %s\n"), 1, gpg_strerror (rc));
          flush_cache_after_error (app);
        }
      else
        app->did_chv1 = 1;
    }

  xfree (pinvalue);

  return rc;
}
```
## Message
Use inline functions to convert buffer data to scalars.

* common/host2net.h (buf16_to_ulong, buf16_to_uint): New.
(buf16_to_ushort, buf16_to_u16): New.
(buf32_to_size_t, buf32_to_ulong, buf32_to_uint, buf32_to_u32): New.
--

Commit 91b826a38880fd8a989318585eb502582636ddd8 was not enough to
avoid all sign extension on shift problems.  Hanno Böck found a case
with an invalid read due to this problem.  To fix that once and for
all almost all uses of "<< 24" and "<< 8" are changed by this patch to
use an inline function from host2net.h.

Signed-off-by: Werner Koch <wk@gnupg.org>
## CWE: `['CWE-20']`

---
## Function 2
```
Function: rend_check_authorization(rend_service_t *service,
                         const char *descriptor_cookie,
                         size_t cookie_len)
{
  rend_authorized_client_t *auth_client = NULL;
  tor_assert(service);
  tor_assert(descriptor_cookie);
  if (!service->clients) {
    log_warn(LD_BUG, "Can't check authorization for a service that has no "
                     "authorized clients configured.");
    return 0;
  }

  if (cookie_len != REND_DESC_COOKIE_LEN) {
    log_info(LD_REND, "Descriptor cookie is %lu bytes, but we expected "
                      "%lu bytes. Dropping cell.",
             (unsigned long)cookie_len, (unsigned long)REND_DESC_COOKIE_LEN);
    return 0;
  }

  /* Look up client authorization by descriptor cookie. */
  SMARTLIST_FOREACH(service->clients, rend_authorized_client_t *, client, {
    if (tor_memeq(client->descriptor_cookie, descriptor_cookie,
                REND_DESC_COOKIE_LEN)) {
      auth_client = client;
      break;
    }
  });
  if (!auth_client) {
    char descriptor_cookie_base64[3*REND_DESC_COOKIE_LEN_BASE64];
    base64_encode(descriptor_cookie_base64, sizeof(descriptor_cookie_base64),
                  descriptor_cookie, REND_DESC_COOKIE_LEN, 0);
    log_info(LD_REND, "No authorization found for descriptor cookie '%s'! "
                      "Dropping cell!",
             descriptor_cookie_base64);
    return 0;
  }

  /* Allow the request. */
  log_info(LD_REND, "Client %s authorized for service %s.",
           auth_client->client_name, service->service_id);
  return 1;
}
```
## Message
Fix log-uninitialized-stack bug in rend_service_intro_established.

Fixes bug 23490; bugfix on 0.2.7.2-alpha.

TROVE-2017-008
CVE-2017-0380
## CWE: `['CWE-532']`

---
## Function 3
```
Function: static apr_status_t h2_session_start(h2_session *session, int *rv)
{
    apr_status_t status = APR_SUCCESS;
    nghttp2_settings_entry settings[3];
    size_t slen;
    int win_size;
    
    ap_assert(session);
    /* Start the conversation by submitting our SETTINGS frame */
    *rv = 0;
    if (session->r) {
        const char *s, *cs;
        apr_size_t dlen; 
        h2_stream * stream;

        /* 'h2c' mode: we should have a 'HTTP2-Settings' header with
         * base64 encoded client settings. */
        s = apr_table_get(session->r->headers_in, "HTTP2-Settings");
        if (!s) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EINVAL, session->r,
                          APLOGNO(02931) 
                          "HTTP2-Settings header missing in request");
            return APR_EINVAL;
        }
        cs = NULL;
        dlen = h2_util_base64url_decode(&cs, s, session->pool);
        
        if (APLOGrdebug(session->r)) {
            char buffer[128];
            h2_util_hex_dump(buffer, 128, (char*)cs, dlen);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, session->r, APLOGNO(03070)
                          "upgrading h2c session with HTTP2-Settings: %s -> %s (%d)",
                          s, buffer, (int)dlen);
        }
        
        *rv = nghttp2_session_upgrade(session->ngh2, (uint8_t*)cs, dlen, NULL);
        if (*rv != 0) {
            status = APR_EINVAL;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, session->r,
                          APLOGNO(02932) "nghttp2_session_upgrade: %s", 
                          nghttp2_strerror(*rv));
            return status;
        }
        
        /* Now we need to auto-open stream 1 for the request we got. */
        stream = h2_session_open_stream(session, 1, 0);
        if (!stream) {
            status = APR_EGENERAL;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, session->r,
                          APLOGNO(02933) "open stream 1: %s", 
                          nghttp2_strerror(*rv));
            return status;
        }
        
        status = h2_stream_set_request_rec(stream, session->r, 1);
        if (status != APR_SUCCESS) {
            return status;
        }
    }

    slen = 0;
    settings[slen].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
    settings[slen].value = (uint32_t)session->max_stream_count;
    ++slen;
    win_size = h2_config_sgeti(session->s, H2_CONF_WIN_SIZE);
    if (win_size != H2_INITIAL_WINDOW_SIZE) {
        settings[slen].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
        settings[slen].value = win_size;
        ++slen;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c, 
                  H2_SSSN_LOG(APLOGNO(03201), session, 
                  "start, INITIAL_WINDOW_SIZE=%ld, MAX_CONCURRENT_STREAMS=%d"), 
                  (long)win_size, (int)session->max_stream_count);
    *rv = nghttp2_submit_settings(session->ngh2, NGHTTP2_FLAG_NONE,
                                  settings, slen);
    if (*rv != 0) {
        status = APR_EGENERAL;
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, session->c,
                      H2_SSSN_LOG(APLOGNO(02935), session, 
                      "nghttp2_submit_settings: %s"), nghttp2_strerror(*rv));
    }
    else {
        /* use maximum possible value for connection window size. We are only
         * interested in per stream flow control. which have the initial window
         * size configured above.
         * Therefore, for our use, the connection window can only get in the
         * way. Example: if we allow 100 streams with a 32KB window each, we
         * buffer up to 3.2 MB of data. Unless we do separate connection window
         * interim updates, any smaller connection window will lead to blocking
         * in DATA flow.
         */
        *rv = nghttp2_submit_window_update(session->ngh2, NGHTTP2_FLAG_NONE,
                                           0, NGHTTP2_MAX_WINDOW_SIZE - win_size);
        if (*rv != 0) {
            status = APR_EGENERAL;
            ap_log_cerror(APLOG_MARK, APLOG_ERR, status, session->c,
                          H2_SSSN_LOG(APLOGNO(02970), session,
                          "nghttp2_submit_window_update: %s"), 
                          nghttp2_strerror(*rv));        
        }
    }
    
    return status;
}
```
## Message
* fixes Timeout vs. KeepAliveTimeout behaviour, see PR 63534 (for trunk now,
   mpm event backport to 2.4.x up for vote).
 * Fixes stream cleanup when connection throttling is in place.
 * Counts stream resets by client on streams initiated by client as cause
   for connection throttling.
 * Header length checks are now logged similar to HTTP/1.1 protocol handler (thanks @mkaufmann)
 * Header length is checked also on the merged value from several header instances
   and results in a 431 response.
## CWE: `['CWE-770']`

---
## Function 4
```
Function: static void vnc_dpy_switch(DisplayChangeListener *dcl,
                           DisplaySurface *surface)
{
    static const char placeholder_msg[] =
        "Display output is not active.";
    static DisplaySurface *placeholder;
    VncDisplay *vd = container_of(dcl, VncDisplay, dcl);
    bool pageflip = vnc_check_pageflip(vd->ds, surface);
    VncState *vs;

    if (surface == NULL) {
        if (placeholder == NULL) {
            placeholder = qemu_create_message_surface(640, 480, placeholder_msg);
        }
        surface = placeholder;
    }

    vnc_abort_display_jobs(vd);
    vd->ds = surface;

    /* guest surface */
    qemu_pixman_image_unref(vd->guest.fb);
    vd->guest.fb = pixman_image_ref(surface->image);
    vd->guest.format = surface->format;

    if (pageflip) {
        vnc_set_area_dirty(vd->guest.dirty, vd, 0, 0,
                           surface_width(surface),
                           surface_height(surface));
        return;
    }

    /* server surface */
    vnc_update_server_surface(vd);

    QTAILQ_FOREACH(vs, &vd->clients, next) {
        vnc_colordepth(vs);
        vnc_desktop_resize(vs);
        if (vs->vd->cursor) {
            vnc_cursor_define(vs);
        }
        memset(vs->dirty, 0x00, sizeof(vs->dirty));
        vnc_set_area_dirty(vs->dirty, vd, 0, 0,
                           vnc_width(vd),
                           vnc_height(vd));
        vnc_update_throttle_offset(vs);
    }
}
```
## Message
vnc: fix memory leak when vnc disconnect

Currently when qemu receives a vnc connect, it creates a 'VncState' to
represent this connection. In 'vnc_worker_thread_loop' it creates a
local 'VncState'. The connection 'VcnState' and local 'VncState' exchange
data in 'vnc_async_encoding_start' and 'vnc_async_encoding_end'.
In 'zrle_compress_data' it calls 'deflateInit2' to allocate the libz library
opaque data. The 'VncState' used in 'zrle_compress_data' is the local
'VncState'. In 'vnc_zrle_clear' it calls 'deflateEnd' to free the libz
library opaque data. The 'VncState' used in 'vnc_zrle_clear' is the connection
'VncState'. In currently implementation there will be a memory leak when the
vnc disconnect. Following is the asan output backtrack:

Direct leak of 29760 byte(s) in 5 object(s) allocated from:
    0 0xffffa67ef3c3 in __interceptor_calloc (/lib64/libasan.so.4+0xd33c3)
    1 0xffffa65071cb in g_malloc0 (/lib64/libglib-2.0.so.0+0x571cb)
    2 0xffffa5e968f7 in deflateInit2_ (/lib64/libz.so.1+0x78f7)
    3 0xaaaacec58613 in zrle_compress_data ui/vnc-enc-zrle.c:87
    4 0xaaaacec58613 in zrle_send_framebuffer_update ui/vnc-enc-zrle.c:344
    5 0xaaaacec34e77 in vnc_send_framebuffer_update ui/vnc.c:919
    6 0xaaaacec5e023 in vnc_worker_thread_loop ui/vnc-jobs.c:271
    7 0xaaaacec5e5e7 in vnc_worker_thread ui/vnc-jobs.c:340
    8 0xaaaacee4d3c3 in qemu_thread_start util/qemu-thread-posix.c:502
    9 0xffffa544e8bb in start_thread (/lib64/libpthread.so.0+0x78bb)
    10 0xffffa53965cb in thread_start (/lib64/libc.so.6+0xd55cb)

This is because the opaque allocated in 'deflateInit2' is not freed in
'deflateEnd'. The reason is that the 'deflateEnd' calls 'deflateStateCheck'
and in the latter will check whether 's->strm != strm'(libz's data structure).
This check will be true so in 'deflateEnd' it just return 'Z_STREAM_ERROR' and
not free the data allocated in 'deflateInit2'.

The reason this happens is that the 'VncState' contains the whole 'VncZrle',
so when calling 'deflateInit2', the 's->strm' will be the local address.
So 's->strm != strm' will be true.

To fix this issue, we need to make 'zrle' of 'VncState' to be a pointer.
Then the connection 'VncState' and local 'VncState' exchange mechanism will
work as expection. The 'tight' of 'VncState' has the same issue, let's also turn
it to a pointer.

Reported-by: Ying Fang <fangying1@huawei.com>
Signed-off-by: Li Qiang <liq3ea@163.com>
Message-id: 20190831153922.121308-1-liq3ea@163.com
Signed-off-by: Gerd Hoffmann <kraxel@redhat.com>
## CWE: `['CWE-401']`

---
## Function 5
```
Function: EXPORTED int specialuse_validate(const char *mboxname, const char *userid,
                                 const char *src, struct buf *dest)
{
    const char *specialuse_extra_opt = config_getstring(IMAPOPT_SPECIALUSE_EXTRA);
    char *strval = NULL;
    strarray_t *valid = NULL;
    strarray_t *new_attribs = NULL;
    strarray_t *cur_attribs = NULL;
    struct buf mbattribs = BUF_INITIALIZER;
    int i, j;
    int r = 0;

    if (!src) {
        buf_reset(dest);
        return 0;
    }

    /* If there is a valid mboxname, we get the current specialuse annotations.
     */
    if (mboxname) {
        annotatemore_lookup(mboxname, "/specialuse", userid, &mbattribs);
        if (mbattribs.len) {
            cur_attribs = strarray_split(buf_cstring(&mbattribs), NULL, 0);
        }
    }

    /* check specialuse_extra option if set */
    if (specialuse_extra_opt)
        valid = strarray_split(specialuse_extra_opt, NULL, 0);
    else
        valid = strarray_new();

    /* strarray_add(valid, "\\All"); -- we don't support virtual folders right now */
    strarray_add(valid, "\\Archive");
    strarray_add(valid, "\\Drafts");
    /* strarray_add(valid, "\\Flagged"); -- we don't support virtual folders right now */
    strarray_add(valid, "\\Important"); // draft-ietf-specialuse-important
    strarray_add(valid, "\\Junk");
    strarray_add(valid, "\\Sent");
    strarray_add(valid, "\\Trash");
    strarray_add(valid, "\\Snoozed"); // JMAP

    new_attribs = strarray_split(src, NULL, 0);

    for (i = 0; i < new_attribs->count; i++) {
        int skip_mbcheck = 0;
        const char *item = strarray_nth(new_attribs, i);

        for (j = 0; j < valid->count; j++) { /* can't use find here */
            if (!strcasecmp(strarray_nth(valid, j), item))
                break;
            /* or without the leading '\' */
            if (!strcasecmp(strarray_nth(valid, j) + 1, item))
                break;
        }

        if (j >= valid->count) {
            r = IMAP_ANNOTATION_BADENTRY;
            goto done;
        }

        if (cur_attribs &&
            (strarray_find_case(cur_attribs, strarray_nth(valid, j), 0) >= 0)) {
            /* The mailbox has this specialuse attribute set already */
            skip_mbcheck = 1;
        }

        /* don't allow names that are already in use */
        if (!skip_mbcheck) {
            char *mbname = mboxlist_find_specialuse(strarray_nth(valid, j),
                                                    userid);
            if (mbname) {
                free(mbname);
                r = IMAP_MAILBOX_SPECIALUSE;
                goto done;
            }
        }

        /* normalise the value */
        strarray_set(new_attribs, i, strarray_nth(valid, j));
    }

    strval = strarray_join(new_attribs, " ");
    buf_setcstr(dest, strval);

done:
    free(strval);
    strarray_free(valid);
    strarray_free(new_attribs);
    strarray_free(cur_attribs);
    buf_free(&mbattribs);
    return r;
}
```
## Message
annotate: don't allow everyone to write shared server entries
## CWE: `['CWE-732']`

---