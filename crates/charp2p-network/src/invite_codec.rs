use std::io;

use charp2p_core::{
    InviteRequest, InviteResponse, MAX_INVITE_REQUEST_WIRE_BYTES, MAX_INVITE_RESPONSE_WIRE_BYTES,
};
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};

use crate::join_codec::{invalid_data, read_bounded};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct InviteCodec;

impl request_response::Codec for InviteCodec {
    type Protocol = StreamProtocol;
    type Request = InviteRequest;
    type Response = InviteResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let encoded = read_bounded(io, MAX_INVITE_REQUEST_WIRE_BYTES).await?;
        InviteRequest::decode(encoded.as_slice()).map_err(invalid_data)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let encoded = read_bounded(io, MAX_INVITE_RESPONSE_WIRE_BYTES).await?;
        InviteResponse::decode(encoded.as_slice()).map_err(invalid_data)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(request.encode().as_slice()).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(response.encode().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::{request_response::Codec, swarm::StreamProtocol};

    use super::InviteCodec;
    use charp2p_core::{
        GroupIdentity, InviteRejectReason, InviteRequest, InviteResponse,
        MAX_INVITE_RESPONSE_WIRE_BYTES,
    };

    #[tokio::test]
    async fn codec_round_trips_an_invite_request_and_rejection() {
        let protocol = StreamProtocol::new("/charp2p/invite/1.0.0");
        let request = InviteRequest::new(GroupIdentity::generate().group_id(), 86_400).unwrap();
        let mut encoded = Cursor::new(Vec::new());
        InviteCodec
            .write_request(&protocol, &mut encoded, request)
            .await
            .unwrap();
        encoded.set_position(0);
        let decoded = InviteCodec
            .read_request(&protocol, &mut encoded)
            .await
            .unwrap();
        assert_eq!(decoded, request);

        let mut encoded = Cursor::new(Vec::new());
        InviteCodec
            .write_response(
                &protocol,
                &mut encoded,
                InviteResponse::rejected(InviteRejectReason::Busy),
            )
            .await
            .unwrap();
        encoded.set_position(0);
        let decoded = InviteCodec
            .read_response(&protocol, &mut encoded)
            .await
            .unwrap();
        assert_eq!(decoded.rejection(), Some(InviteRejectReason::Busy));
    }

    #[tokio::test]
    async fn codec_rejects_a_response_larger_than_the_outer_bound() {
        let protocol = StreamProtocol::new("/charp2p/invite/1.0.0");
        let mut encoded = Cursor::new(vec![0; MAX_INVITE_RESPONSE_WIRE_BYTES + 1]);

        let error = InviteCodec
            .read_response(&protocol, &mut encoded)
            .await
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
