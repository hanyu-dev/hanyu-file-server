//! PoC

#![feature(cold_path)]

mod response;

use std::{io, sync::Arc};

use anyhow::{Context, Result, anyhow};
use http::{HeaderName, StatusCode, header::CONNECTION};
use ktls::CorkStream;
use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tracing::Instrument;

#[tokio::main]
async fn main() -> Result<()> {
    macro_toolset::init_tracing_simple!();

    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let crt = certified_key.cert.der();
    let key = certified_key.key_pair.serialize_der();

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![crt.clone()],
            PrivatePkcs8KeyDer::from(key.clone()).into(),
        )
        .unwrap();

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    server_config.enable_secret_extraction = true;

    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("0.0.0.0:5443").await?;

    let h = tokio::spawn(async move {
        loop {
            let (mut incoming, remote_addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    tracing::debug!("Connection aborted.");
                    continue;
                }
                Err(e) => {
                    tracing::error!("Failed to accept: {:#?}", e);
                    break Err::<(), _>(anyhow!(e));
                }
            };

            let acceptor = acceptor.clone();

            let h = async move {
                tracing::debug!("Accepted request: {:?}", remote_addr);

                let tls_stream = acceptor.accept(CorkStream::new(incoming)).await?;

                tracing::debug!("Accepted request: TLS: {:?}", remote_addr);

                {
                    let sc = tls_stream.get_ref().1;
                    let alpn_proto = sc
                        .alpn_protocol()
                        .and_then(|p| std::str::from_utf8(p).ok().map(|s| s.to_string()));
                    tracing::debug!(?alpn_proto, ?remote_addr, "Performed TLS handshake");
                }

                // this extracts the secrets, configures kTLS as the "ULP"
                // (upper-layer protocol), and returns a `TcpStream` that
                // transparently does TLS.
                let mut tls_stream = ktls::Setup::new_server_stream(tls_stream);

                let tls_stream = match tls_stream.execute().await {
                    Ok(tls_stream) => {
                        tracing::debug!("kTLS successfully set up");
                        tls_stream
                    }
                    Err(e) => {
                        if let Some((_drained, ktls::setup::TlsStream::Server(mut stream))) =
                            tls_stream.try_recover()
                        {
                            tracing::debug!(
                                _drained = ?_drained,
                                "kTLS failed to set up, but we can still use the stream"
                            );
                            stream.write_all(b"HTTP/1.1 500 OK\r\n\r\n").await?;
                            stream.flush().await?;
                            stream.shutdown().await?;

                            return Ok(());
                        } else {
                            tracing::error!("Failed to set up kTLS: {:#?}", e);
                            return Err(anyhow!(e));
                        }
                    }
                };

                tracing::debug!(
                    "Accepted request: KTLS config_ktls_server: {:?}",
                    remote_addr
                );

                tracing::debug!("kTLS successfully set up");
                let (drained, mut incoming) = tls_stream.into_raw();
                let mut drained_as_buffer = drained.unwrap_or_default();
                tracing::debug!(
                    ?remote_addr,
                    "{} bytes already decoded by rustls",
                    drained_as_buffer.len()
                );

                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut req = httparse::Request::new(&mut headers);
                let body_from_idx;

                loop {
                    let len = drained_as_buffer.len();

                    #[allow(unsafe_code, reason = "Will not modify the buffer")]
                    let existing_content =
                        unsafe { std::slice::from_raw_parts(drained_as_buffer.as_ptr(), len) };

                    match req.parse(&existing_content).map_err(|_| {
                        tracing::error!(
                            "{}",
                            String::from_utf8_lossy(&drained_as_buffer).to_string()
                        );

                        anyhow!("chunk error")
                    })? {
                        httparse::Status::Complete(s) => {
                            if let Some(p) = req.headers.iter().find(|&p| {
                                HeaderName::from_bytes(p.name.as_bytes())
                                    .is_ok_and(|p| p == CONNECTION)
                            }) {
                                if p.value == b"keep-alive" {
                                    let mut file =
                                        tokio::fs::File::open("./.test/test.mp4").await?;

                                    let file_length = file.metadata().await?.len();

                                    tracing::debug!("Keep-alive connection, writing data!");

                                    let body = response::SpliceIoBody::new_with_file_len(
                                        &mut file,
                                        file_length,
                                        None,
                                        None,
                                    )?;

                                    let transferred = response::Response {
                                        status: StatusCode::OK,
                                        headers: None,
                                    }
                                    .write_to_stream(&mut incoming, Some(body))
                                    .await?;

                                    tracing::debug!(
                                        file_length,
                                        transferred,
                                        "Keep-alive connection, writing data 0 done!"
                                    );

                                    drained_as_buffer.clear();

                                    // Ignore the body!

                                    continue;
                                }
                            }

                            body_from_idx = s;

                            break;
                        }
                        httparse::Status::Partial => {
                            tracing::debug!("Partial chunk, waiting for more data");

                            drained_as_buffer.resize(len + 512, 0);

                            let n = incoming
                                .read_buf(&mut &mut drained_as_buffer[len..])
                                .await
                                .context("read error")?;

                            if n == 0 {
                                tracing::debug!("EOF, closing connection");
                                return Ok(());
                            }

                            drained_as_buffer.truncate(len + n);
                        }
                    }
                }

                tracing::debug!("Parsed request: {:?}", req);

                incoming.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;

                Ok::<_, anyhow::Error>(())
            }
            .instrument(tracing::span!(
                tracing::Level::DEBUG,
                "handle_request",
                ?remote_addr
            ));

            tokio::spawn(async move {
                h.await.inspect_err(|e| {
                    tracing::error!("Error handling request: {:#?}", e);
                });
            });
        }
    });

    let _ = tokio::join!(h);

    Ok(())
}
