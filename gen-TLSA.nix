{ cacert, openssl, runCommandNoCC }:

names:

runCommandNoCC
  "gen-TLSA"
  {
    __structuredAttrs = true;
    buildInputs = [ openssl ];
    inherit names;
  }
  ''
    for name in "''${names[@]}"; do
      printf "@ TLSA 0 1 2 " >>$out
      openssl x509 -in ${cacert.unbundled}/etc/ssl/certs/"$name":*.crt -noout \
        -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha512 -hex |
        cut -f 2 -d " " >>$out
    done
  ''
