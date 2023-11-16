
module FINGERPRINT::JA4S;

export {
  # The server fingerprint context and logging format
  type Info: record {

    # The connection uid which this fingerprint represents
    uid: string &log &optional;

    # The server hello fingerprint
    ja4s: string &log &default="";

    # The server hello fingerprint in raw format
    r: string &log &default="";
  
    # If this context is ready to be logged
    done: bool &default=F;
  };

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4s: event(rec: Info);
  global log_policy: Log::PolicyHook;
}

redef record FINGERPRINT::Info += {
  ja4s: FINGERPRINT::JA4S::Info &default=[];
};

event zeek_init() &priority=5 {
  # ServerHello fingerprints are logged to a new file instead of appended to ssl.log
  Log::create_stream(FINGERPRINT::JA4S::LOG,
    [$columns=FINGERPRINT::JA4S::Info, $ev=log_fingerprint_ja4s, $path="fingerprint_ja4s", $policy=log_policy]
  );
}

# TODO - some of the following functions are duplicates from the ClientHello code, vector_of_count_to_str. 
#  reduce, reuse, recycle these function
function vector_of_count_to_str(input: vector of count, format_str: string &default="%04x", dlimit: string &default=","): string {
  local output: string = "";
  for (idx, val in input) {
    output += fmt(format_str, val);
    if (idx < |input|-1) {
      output += dlimit;
    }
  }
  return output;
}

function make_a(c: connection): string {
  local proto: string = "0";
  if (c$conn$proto == tcp) {
    proto = "t";
  # TODO - does this even work? which quic analzyer do i need to use for testing?
  } else if (c$conn$proto == udp && "gquic" in c$service) {
    proto = "q";
  }

  local ec_count = "00";
  if (|c$fp$server_hello$extension_codes| > 99) {
    ec_count = cat(99);
  } else {
    ec_count = fmt("%02d", |c$fp$server_hello$extension_codes|);
  }

  local alpn: string = "00";
  if (c$fp$server_hello?$alpns && |c$fp$server_hello$alpns| > 0) {
    # TODO - There should be only 1. what happens if there are more than 1?
    alpn = c$fp$client_hello$alpns[0];
  }

  local a: string = "";
  a += proto;
  a += FINGERPRINT::TLS_VERSION_MAPPER[c$fp$server_hello$version];
  a += ec_count;
  a += alpn;
  return a;
}

function make_b(c: connection): string {
  return to_lower(fmt("%02x", c$fp$server_hello$cipher_suite));
}

function make_c(c: connection): string {
  local input: vector of count = c$fp$server_hello$extension_codes;
  local sha256_object = sha256_hash_init();
  sha256_hash_update(sha256_object, vector_of_count_to_str(input));
  return sha256_hash_finish(sha256_object)[:12];
}

event connection_state_remove(c: connection) {
  if (!c?$fp || !c$fp?$server_hello || !c$fp$server_hello?$version) { return; }

  local a: string = make_a(c);
  local b: string = make_b(c);

  c$fp$ja4s$uid = c$uid;

  # ja4s
  c$fp$ja4s$ja4s += a;
  c$fp$ja4s$ja4s += FINGERPRINT::delimiter;
  c$fp$ja4s$ja4s += b;
  c$fp$ja4s$ja4s += FINGERPRINT::delimiter;
  c$fp$ja4s$ja4s += make_c(c);

  # ja4s_r
  c$fp$ja4s$r += a;
  c$fp$ja4s$r += FINGERPRINT::delimiter;
  c$fp$ja4s$r += b;
  c$fp$ja4s$r += FINGERPRINT::delimiter;
  c$fp$ja4s$r += vector_of_count_to_str(c$fp$server_hello$extension_codes);

  c$fp$ja4s$done = T;
  Log::write(FINGERPRINT::JA4S::LOG, c$fp$ja4s);
}
