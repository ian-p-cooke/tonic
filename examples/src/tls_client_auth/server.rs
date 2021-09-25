pub mod pb {
    tonic::include_proto!("grpc.examples.echo");
}

use futures::Stream;
use pb::{EchoRequest, EchoResponse};
use std::pin::Pin;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use x509_parser::extensions::{ParsedExtension, GeneralName};

type EchoResult<T> = Result<Response<T>, Status>;
type ResponseStream = Pin<Box<dyn Stream<Item = Result<EchoResponse, Status>> + Send + Sync>>;

#[derive(Default)]
pub struct EchoServer;

#[tonic::async_trait]
impl pb::echo_server::Echo for EchoServer {
    async fn unary_echo(&self, request: Request<EchoRequest>) -> EchoResult<EchoResponse> {
        let certs = request
            .peer_certs()
            .expect("Client did not send its certs!");

        println!("Got {} peer certs!", certs.len());

        let (_, client_certificate) = x509_parser::parse_x509_certificate(&certs[0].get_ref()).unwrap();

        // the client's DN
        println!("{}", client_certificate.subject());

        // find email in SAN if available
        for ext in client_certificate.extensions() {
            let parsed_ext = ext.parsed_extension();
            if let ParsedExtension::SubjectAlternativeName(san) = parsed_ext {
                for name in &san.general_names {
                    if let GeneralName::RFC822Name(email) = name {
                        println!("found email SAN: {}", email);
                    }
                }
            }
        }

        let message = request.into_inner().message;
        Ok(Response::new(EchoResponse { message }))
    }

    type ServerStreamingEchoStream = ResponseStream;

    async fn server_streaming_echo(
        &self,
        _: Request<EchoRequest>,
    ) -> Result<Response<Self::ServerStreamingEchoStream>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    async fn client_streaming_echo(
        &self,
        _: Request<tonic::Streaming<EchoRequest>>,
    ) -> Result<Response<EchoResponse>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }

    type BidirectionalStreamingEchoStream = ResponseStream;

    async fn bidirectional_streaming_echo(
        &self,
        _: Request<tonic::Streaming<EchoRequest>>,
    ) -> Result<Response<Self::BidirectionalStreamingEchoStream>, Status> {
        Err(Status::unimplemented("Not yet implemented"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert = tokio::fs::read("examples/data/tls/server.pem").await?;
    let key = tokio::fs::read("examples/data/tls/server.key").await?;
    let server_identity = Identity::from_pem(cert, key);

    let client_ca_cert = tokio::fs::read("examples/data/tls/client_ca.pem").await?;
    let client_ca_cert = Certificate::from_pem(client_ca_cert);

    let addr = "[::1]:50051".parse().unwrap();
    let server = EchoServer::default();

    let tls = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(client_ca_cert);

    Server::builder()
        .tls_config(tls)?
        .add_service(pb::echo_server::EchoServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}
