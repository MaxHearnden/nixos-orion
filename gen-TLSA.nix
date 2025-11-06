{
  cacert,
  names,
  tlsa_usage ? 0,
  tlsa_selector ? 1,
  tlsa_matching ? 2,
  openssl,
  runCommandNoCC,
  xxd
}:

runCommandNoCC
  "gen-TLSA"
  {
    __structuredAttrs = true;
    buildInputs = [ openssl xxd ];
    inherit names tlsa_usage tlsa_selector tlsa_matching;
  }
  ''
    for name in "''${names[@]}"; do
      echo "; $name" >>$out
      printf "@ TLSA $tlsa_usage $tlsa_selector $tlsa_matching " >>$out
      if [ "$tlsa_selector" = 1 ]; then
        openssl x509 -in ${cacert.unbundled}/etc/ssl/certs/"$name":*.crt \
          -noout -pubkey | openssl pkey -pubin -outform DER >content
      else
        openssl x509 -in ${cacert.unbundled}/etc/ssl/certs/"$name":*.crt \
          -outform DER >content
      fi

      if [ "$tlsa_matching" = 0 ]; then
        xxd -p -c 0 <content >>$out
      elif [ "$tlsa_matching" = 1 ]; then
        openssl dgst -sha256 -hex <content | cut -f 2 -d " " >>$out
      elif [ "$tlsa_matching" = 2 ]; then
        openssl dgst -sha512 -hex <content | cut -f 2 -d " " >>$out
      fi
    done
  ''
