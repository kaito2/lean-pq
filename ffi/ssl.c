/*
  LeanPQ SSL/TLS support — C FFI wrapper for OpenSSL.

  Provides functions callable from Lean 4 to establish and use TLS connections
  over existing TCP sockets (file descriptors).

  Build note: link with -lssl -lcrypto.
  On macOS with Homebrew: -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib
*/

#include <lean/lean.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>

/* ============================================================
   Option construction helpers.

   In Lean 4's runtime representation:
     Option.none  = lean_box(0)          (scalar, constructor index 0)
     Option.some a = ctor(1, [a])        (constructor index 1, one object field)
   ============================================================ */

static inline lean_obj_res mk_option_none(void) {
    return lean_box(0);
}

static inline lean_obj_res mk_option_some(lean_obj_res val) {
    lean_obj_res obj = lean_alloc_ctor(1, 1, 0);
    lean_ctor_set(obj, 0, val);
    return obj;
}

/* ============================================================
   External class registration (opaque Lean types with finalizers)
   ============================================================ */

static lean_external_class *g_ssl_ctx_class = NULL;
static lean_external_class *g_ssl_conn_class = NULL;

/* Finalizer: free an SSL_CTX when the Lean object is garbage-collected. */
static void ssl_ctx_finalizer(void *ptr) {
    if (ptr) {
        SSL_CTX_free((SSL_CTX *)ptr);
    }
}

/* Finalizer: free an SSL (connection) when the Lean object is garbage-collected. */
static void ssl_conn_finalizer(void *ptr) {
    if (ptr) {
        SSL_free((SSL *)ptr);
    }
}

/* no-op foreach for external classes */
static void ssl_noop_foreach(void *mod, b_lean_obj_arg fn) {
    (void)mod;
    (void)fn;
}

/* Ensure the external classes are registered exactly once. */
static void ensure_classes_registered(void) {
    if (g_ssl_ctx_class == NULL) {
        g_ssl_ctx_class = lean_register_external_class(
            ssl_ctx_finalizer, ssl_noop_foreach);
    }
    if (g_ssl_conn_class == NULL) {
        g_ssl_conn_class = lean_register_external_class(
            ssl_conn_finalizer, ssl_noop_foreach);
    }
}

/* ============================================================
   Helper: build an IO error result from OpenSSL's error queue.
   ============================================================ */

static lean_obj_res mk_ssl_error(const char *prefix) {
    char buf[256];
    unsigned long err = ERR_get_error();
    if (err != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
    } else {
        strncpy(buf, "unknown SSL error", sizeof(buf));
        buf[sizeof(buf) - 1] = '\0';
    }
    /* Clear remaining errors from the queue */
    ERR_clear_error();

    /* Build the error string: "prefix: detail" */
    size_t prefix_len = strlen(prefix);
    size_t buf_len = strlen(buf);
    size_t total = prefix_len + 2 + buf_len; /* ": " */
    char *msg = malloc(total + 1);
    if (msg) {
        memcpy(msg, prefix, prefix_len);
        msg[prefix_len] = ':';
        msg[prefix_len + 1] = ' ';
        memcpy(msg + prefix_len + 2, buf, buf_len);
        msg[total] = '\0';
    }
    lean_obj_res lean_msg = lean_mk_string(msg ? msg : prefix);
    free(msg);
    return lean_io_result_mk_error(lean_mk_io_user_error(lean_msg));
}

/* ============================================================
   lean_pq_ssl_ctx_new : IO SSLContext
   ============================================================ */

LEAN_EXPORT lean_obj_res lean_pq_ssl_ctx_new(lean_obj_arg world) {
    (void)world;
    ensure_classes_registered();

    const SSL_METHOD *method = TLS_client_method();
    if (!method) {
        return mk_ssl_error("SSL_CTX_new: failed to get TLS client method");
    }

    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        return mk_ssl_error("SSL_CTX_new: failed to create context");
    }

    /* Set reasonable defaults */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_default_verify_paths(ctx);

    lean_obj_res obj = lean_alloc_external(g_ssl_ctx_class, ctx);
    return lean_io_result_mk_ok(obj);
}

/* ============================================================
   lean_pq_ssl_connect : @& SSLContext -> UInt32 -> IO SSLConnection
   ============================================================ */

LEAN_EXPORT lean_obj_res lean_pq_ssl_connect(lean_obj_arg ctx_obj, uint32_t fd, lean_obj_arg world) {
    (void)world;
    ensure_classes_registered();

    SSL_CTX *ctx = (SSL_CTX *)lean_get_external_data(ctx_obj);
    if (!ctx) {
        return lean_io_result_mk_error(
            lean_mk_io_user_error(lean_mk_string("SSL_connect: invalid SSL context")));
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        return mk_ssl_error("SSL_new: failed to create SSL object");
    }

    if (SSL_set_fd(ssl, (int)fd) != 1) {
        SSL_free(ssl);
        return mk_ssl_error("SSL_set_fd: failed to attach file descriptor");
    }

    int ret = SSL_connect(ssl);
    if (ret != 1) {
        int ssl_err = SSL_get_error(ssl, ret);
        SSL_free(ssl);
        char detail[128];
        snprintf(detail, sizeof(detail), "SSL_connect: handshake failed (SSL_error=%d)", ssl_err);
        /* Push our own detail so mk_ssl_error picks up the queue or our message */
        unsigned long queued = ERR_peek_error();
        if (queued != 0) {
            return mk_ssl_error(detail);
        }
        return lean_io_result_mk_error(
            lean_mk_io_user_error(lean_mk_string(detail)));
    }

    lean_obj_res obj = lean_alloc_external(g_ssl_conn_class, ssl);
    return lean_io_result_mk_ok(obj);
}

/* ============================================================
   lean_pq_ssl_send : @& SSLConnection -> @& ByteArray -> IO Unit
   ============================================================ */

LEAN_EXPORT lean_obj_res lean_pq_ssl_send(lean_obj_arg conn_obj, b_lean_obj_arg data, lean_obj_arg world) {
    (void)world;

    SSL *ssl = (SSL *)lean_get_external_data(conn_obj);
    if (!ssl) {
        return lean_io_result_mk_error(
            lean_mk_io_user_error(lean_mk_string("SSL_send: invalid SSL connection")));
    }

    lean_sarray_object *arr = lean_to_sarray(data);
    const uint8_t *buf = arr->m_data;
    size_t total = arr->m_size;
    size_t sent = 0;

    while (sent < total) {
        int chunk = (int)(total - sent);
        /* SSL_write may not accept more than INT_MAX at once */
        if (chunk > (1 << 30)) chunk = (1 << 30);

        int n = SSL_write(ssl, buf + sent, chunk);
        if (n <= 0) {
            return mk_ssl_error("SSL_write: failed to send data");
        }
        sent += (size_t)n;
    }

    return lean_io_result_mk_ok(lean_box(0));
}

/* ============================================================
   lean_pq_ssl_recv : @& SSLConnection -> UInt64 -> IO (Option ByteArray)
   ============================================================ */

LEAN_EXPORT lean_obj_res lean_pq_ssl_recv(lean_obj_arg conn_obj, uint64_t max_bytes, lean_obj_arg world) {
    (void)world;

    SSL *ssl = (SSL *)lean_get_external_data(conn_obj);
    if (!ssl) {
        return lean_io_result_mk_error(
            lean_mk_io_user_error(lean_mk_string("SSL_recv: invalid SSL connection")));
    }

    /* Cap allocation to a reasonable size */
    size_t alloc_size = (size_t)max_bytes;
    if (alloc_size > (16 * 1024 * 1024)) {
        alloc_size = 16 * 1024 * 1024;
    }

    uint8_t *buf = malloc(alloc_size);
    if (!buf) {
        return lean_io_result_mk_error(
            lean_mk_io_user_error(lean_mk_string("SSL_recv: out of memory")));
    }

    int n = SSL_read(ssl, buf, (int)(alloc_size > (size_t)INT32_MAX ? INT32_MAX : alloc_size));

    if (n < 0) {
        int ssl_err = SSL_get_error(ssl, n);
        free(buf);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            /* Would block — treat as empty for now (non-blocking support) */
            /* Return none */
            return lean_io_result_mk_ok(mk_option_none());
        }
        return mk_ssl_error("SSL_read: failed to receive data");
    }

    if (n == 0) {
        /* Connection closed cleanly */
        free(buf);
        return lean_io_result_mk_ok(mk_option_none());
    }

    /* Build a Lean ByteArray from the received bytes */
    lean_obj_res byte_array = lean_alloc_sarray(1, (size_t)n, (size_t)n);
    memcpy(lean_sarray_cptr(byte_array), buf, (size_t)n);
    free(buf);

    /* Return some byte_array */
    lean_obj_res some = mk_option_some(byte_array);
    return lean_io_result_mk_ok(some);
}

/* ============================================================
   lean_pq_ssl_shutdown : @& SSLConnection -> IO Unit
   ============================================================ */

LEAN_EXPORT lean_obj_res lean_pq_ssl_shutdown(lean_obj_arg conn_obj, lean_obj_arg world) {
    (void)world;

    SSL *ssl = (SSL *)lean_get_external_data(conn_obj);
    if (!ssl) {
        return lean_io_result_mk_ok(lean_box(0));
    }

    /*
     * SSL_shutdown returns:
     *   0 = sent close_notify, need to call again for bidirectional shutdown
     *   1 = fully shut down
     *  <0 = error
     *
     * For a client library we do a best-effort bidirectional shutdown.
     */
    int ret = SSL_shutdown(ssl);
    if (ret == 0) {
        /* Call again for bidirectional shutdown */
        SSL_shutdown(ssl);
    }

    return lean_io_result_mk_ok(lean_box(0));
}

/* ============================================================
   lean_pq_socket_fd : Socket -> IO UInt32

   Extracts the underlying file descriptor from a Lean TCP socket.
   The Lean 4 runtime stores sockets as boxed file descriptors;
   this function extracts the integer fd value.

   NOTE: The exact internal representation may change across Lean
   versions. This implementation assumes the socket object wraps
   a file descriptor accessible via lean_unbox_uint32 or as a
   scalar in the object. Adjust if the Lean runtime changes.
   ============================================================ */

LEAN_EXPORT lean_obj_res lean_pq_socket_fd(lean_obj_arg socket, lean_obj_arg world) {
    (void)world;

    /*
     * In Lean 4's standard library (Std.Internal.IO.Async),
     * TCP.Socket.Client is an opaque type wrapping a file descriptor.
     * We try to extract it as an external object holding an int,
     * or as a boxed scalar. This is necessarily implementation-dependent.
     *
     * Common approach: the socket stores its fd as a UInt32 or Int32.
     * We attempt lean_ctor_get on the structure fields.
     */
    if (lean_is_scalar(socket)) {
        /* If it's a scalar, it is directly the fd value */
        uint32_t fd = (uint32_t)lean_unbox(socket);
        return lean_io_result_mk_ok(lean_box_uint32(fd));
    }

    /*
     * If it's a constructor object, try to get field 0.
     * Many Lean wrappers store the fd as the first field of a structure.
     */
    if (lean_is_ctor(socket)) {
        lean_obj_res field0 = lean_ctor_get(socket, 0);
        if (lean_is_scalar(field0)) {
            uint32_t fd = (uint32_t)lean_unbox(field0);
            return lean_io_result_mk_ok(lean_box_uint32(fd));
        }
    }

    /*
     * If it's an external object, try to interpret the data pointer as an fd.
     * This is a fallback for opaque runtime representations.
     */
    if (lean_is_external(socket)) {
        /* Some implementations store fd as (intptr_t) in external data */
        void *data = lean_get_external_data(socket);
        uint32_t fd = (uint32_t)(intptr_t)data;
        return lean_io_result_mk_ok(lean_box_uint32(fd));
    }

    return lean_io_result_mk_error(
        lean_mk_io_user_error(
            lean_mk_string("lean_pq_socket_fd: could not extract fd from socket object")));
}
