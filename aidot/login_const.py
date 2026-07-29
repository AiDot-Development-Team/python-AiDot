"""Constants for the aidot login."""

APP_ID = "1383974540041977857"

# API URL template - use .format(region="us") to construct
API_URL_TEMPLATE = "https://prod-{region}-api.arnoo.com/v17"
DEFAULT_REGION = "us"

PUBLIC_KEY_PEM = b"""
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtQAnPCi8ksPnS1Du6z96PsKfN
p2Gp/f/bHwlrAdplbX3p7/TnGpnbJGkLq8uRxf6cw+vOthTsZjkPCF7CatRvRnTj
c9fcy7yE0oXa5TloYyXD6GkxgftBbN/movkJJGQCc7gFavuYoAdTRBOyQoXBtm0m
kXMSjXOldI/290b9BQIDAQAB
-----END PUBLIC KEY-----
"""
