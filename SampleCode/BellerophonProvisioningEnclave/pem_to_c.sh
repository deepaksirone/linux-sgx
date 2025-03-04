#!/bin/sh
#
# Convert PEM key to C bytes array for easier use and more security.
#

set -o pipefail
set -e

c_hex() {
    od -t x1 |
    sed -E \
        -e 's|^([[:xdigit:]]+)|/* \1 */ |' \
        -e 's|\b([[:xdigit:]][[:xdigit:]])\b|0x\1,|g'
}

case $1 in
'' | -h | --help)
    echo "usage: ${0##*/} <private.key>" >&2
    exit 1
    ;;
esac

keyfile="$1"

v_privkey=$(openssl rand -hex 8)
v_pubkey=$(openssl rand -hex 8)

privkey=$(openssl pkey -in ${keyfile} -outform DER | c_hex) || exit $?
pubkey=$(openssl pkey -in ${keyfile} -pubout -outform DER | c_hex) || exit $?

cat << _EOF_
#define _PUBKEY _${v_pubkey}
static const unsigned char _${v_pubkey}[] = {
${pubkey}
};

#define _PRIVKEY _${v_privkey}
static const unsigned char _${v_privkey}[] = {
${privkey}
};
_EOF_
