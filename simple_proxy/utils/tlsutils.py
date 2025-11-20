

def alpn_ssl_context_cb(ssl_ctx):
    ssl_ctx.set_alpn_protocols(["h2", "http/1.1"])