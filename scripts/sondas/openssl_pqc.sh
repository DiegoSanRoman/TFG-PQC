#!/bin/sh
# openssl_pqc.sh - Wrapper for OpenSSL with PQC provider support
# This transparently loads the OQS provider before executing OpenSSL commands

exec /opt/openssl/bin/openssl \
    -provider-path /opt/openssl/lib64/ossl-modules \
    -provider oqsprovider \
    -provider default \
    "$@"
