use std::io;

use charp2p_core::{
    JoinRequest, JoinResponse, MAX_JOIN_REQUEST_WIRE_BYTES, MAX_JOIN_RESPONSE_WIRE_BYTES,
};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct JoinCodec;

impl request_response::Codec for JoinCodec {
    type Protocol = StreamProtocol;
    type Request = JoinRequest;
    type Response = JoinResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let encoded = read_bounded(io, MAX_JOIN_REQUEST_WIRE_BYTES).await?;
        JoinRequest::decode(encoded.as_slice()).map_err(invalid_data)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let encoded = read_bounded(io, MAX_JOIN_RESPONSE_WIRE_BYTES).await?;
        JoinResponse::decode(encoded.as_slice()).map_err(invalid_data)
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
        let encoded = request.encode().map_err(invalid_data)?;
        io.write_all(encoded.as_slice()).await
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
        let encoded = response.encode().map_err(invalid_data)?;
        io.write_all(encoded.as_slice()).await
    }
}

async fn read_bounded<T>(io: &mut T, maximum: usize) -> io::Result<Zeroizing<Vec<u8>>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut encoded = Zeroizing::new(Vec::new());
    io.take((maximum as u64) + 1)
        .read_to_end(&mut encoded)
        .await?;
    if encoded.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "join message exceeds its wire limit",
        ));
    }
    Ok(encoded)
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::{request_response::Codec, swarm::StreamProtocol};

    use super::JoinCodec;
    use charp2p_core::{
        DeviceIdentity, GroupIdentity, HistoryPolicy, Invitation, InvitationSpec, JoinRequest,
        MAX_JOIN_REQUEST_WIRE_BYTES,
    };

    const NOW: u64 = 1_800_000_000;

    #[tokio::test]
    async fn codec_round_trips_a_join_request() {
        let invitation = Invitation::issue(
            &GroupIdentity::generate(),
            DeviceIdentity::generate().peer_id(),
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: NOW + 3_600,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            NOW,
        )
        .unwrap();
        let request = JoinRequest::from_invitation(&invitation, vec![1, 2, 3]).unwrap();
        let protocol = StreamProtocol::new("/charp2p/join/1.0.0");
        let mut encoded = Cursor::new(Vec::new());

        JoinCodec
            .write_request(&protocol, &mut encoded, request)
            .await
            .unwrap();
        encoded.set_position(0);
        let decoded = JoinCodec
            .read_request(&protocol, &mut encoded)
            .await
            .unwrap();

        assert_eq!(decoded.group_id(), invitation.group_id());
        assert_eq!(decoded.invitation(), invitation.encode().unwrap());
        assert_eq!(decoded.key_package(), &[1, 2, 3]);
    }

    #[tokio::test]
    async fn codec_rejects_a_message_larger_than_the_outer_bound() {
        let protocol = StreamProtocol::new("/charp2p/join/1.0.0");
        let mut encoded = Cursor::new(vec![0; MAX_JOIN_REQUEST_WIRE_BYTES + 1]);

        let error = JoinCodec
            .read_request(&protocol, &mut encoded)
            .await
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
