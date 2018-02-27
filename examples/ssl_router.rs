extern crate wamp;

use wamp::router::Router;
extern crate env_logger;
#[macro_use]
extern crate log;

extern crate openssl;
use openssl::ssl::{SslAcceptorBuilder, SslMethod};

fn main() {
    env_logger::init();

    // Create an ssl acceptor builder that will build an ssl acceptor using mozilla's
    // intermediate settings (https://wiki.mozilla.org/Security/Server_Side_TLS)
    let mut acceptor_builder =
        SslAcceptorBuilder::mozilla_intermediate_raw(SslMethod::tls()).unwrap();

    // Set certificate chain file to your letsencrypt chain file
    acceptor_builder
        .set_certificate_chain_file("/etc/letsencrypt/live/universalis.exchange/fullchain.pem")
        .unwrap();

    // Set private key to letsencrypt private key
    acceptor_builder
        .set_private_key_file(
            "/etc/letsencrypt/live/universalis.exchange/privkey.pem",
            openssl::x509::X509_FILETYPE_PEM,
        )
        .unwrap();

    // Do not verify peer certificates
    acceptor_builder.set_verify(openssl::ssl::SSL_VERIFY_NONE);

    // Build ssl acceptor that will be passed to all connection handlers
    let acceptor = acceptor_builder.build();

    // Initialize router with ssl acceptor
    let mut router = Router::new_with_ssl(acceptor);
    router.add_realm("realm1");
    info!("Router listening");
    let child = router.listen("192.168.1.43:8090");
    child.join().unwrap();
}
