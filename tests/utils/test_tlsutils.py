from simple_proxy.utils import alpn_ssl_context_cb

def test_alpn_ssl_context_cb(mocker):
    ssl_ctx_mocker = mocker.MagicMock()
    alpn_ssl_context_cb(ssl_ctx_mocker)
    ssl_ctx_mocker.set_alpn_protocols.assert_called_once_with(['h2', 'http/1.1'])
