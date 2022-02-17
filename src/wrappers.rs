use frost_dalek::{Participant, nizk::NizkOfSecretKey, keygen::SecretShare, IndividualSecretKey as SecretKey, precomputation::PublicCommitmentShareList, signature::{Signer, PartialThresholdSignature}, IndividualPublicKey, GroupKey};
use curve25519_dalek::{ristretto::{RistrettoPoint, CompressedRistretto}, scalar::Scalar};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use std::convert::TryInto;

pub(crate) fn scalar_bytes_from_buff(buf: Buffer) -> Option<[u8; 32]> {
    (&buf as &[u8]).try_into().ok()
}

pub(crate) fn group_key_from_buff(buf: Buffer) -> Option<GroupKey> {
    (&buf as &[u8]).try_into().ok()
        .map(|v| GroupKey::from_bytes(v).ok())
        .flatten()
}

fn scalar_from_buff(buf: Buffer) -> Option<Scalar> {
    Some(Scalar::from_bits(
        scalar_bytes_from_buff(buf)?
    ))
}

fn scalar_to_buff(scalar: Scalar) -> Buffer {
    scalar.to_bytes().to_vec().into()
}

fn risteretto_point_to_buff(point: RistrettoPoint) -> Buffer {
    point.compress().to_bytes().to_vec().into()
}

fn risteretto_point_from_buff(buf: Buffer) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(&buf).decompress()
}

#[napi(object)]
pub(crate) struct ParticipantWrapper {
    pub index: u32,
    pub commitments: Vec<Buffer>,
    pub pos_r: Buffer,
    pub pos_s: Buffer
}

#[napi(object)]
pub(crate) struct PublicKeyWrapper {
    pub index: u32,
    pub share: Buffer
}

impl From<IndividualPublicKey> for PublicKeyWrapper {
    fn from(pubk: IndividualPublicKey) -> Self {
        Self {
            index: pubk.index,
            share: risteretto_point_to_buff(pubk.share)
        }
    }
}

impl Into<Option<IndividualPublicKey>> for PublicKeyWrapper {
    fn into(self) -> Option<IndividualPublicKey> {
        Some(IndividualPublicKey {
            index: self.index,
            share: risteretto_point_from_buff(self.share)?
        })
    }
}

impl From<Participant> for ParticipantWrapper {
    fn from(participant: Participant) -> ParticipantWrapper {
        ParticipantWrapper {
            index: participant.index,
            commitments: participant.commitments
                .into_iter()
                .map(|p| risteretto_point_to_buff(p.into()))
                .collect(),
            pos_r: scalar_to_buff(participant.proof_of_secret_key.r),
            pos_s: scalar_to_buff(participant.proof_of_secret_key.s)
        }
    }
}

impl Into<Option<Participant>> for ParticipantWrapper {
    fn into(self: ParticipantWrapper) -> Option<Participant> {
        Some(Participant {
            index: self.index,
            commitments: self.commitments
                .into_iter()
                .map(|p| risteretto_point_from_buff(p).map(|v| v.into()))
                .collect::<Option<Vec<_>>>()?,
            proof_of_secret_key: NizkOfSecretKey {
                s: scalar_from_buff(self.pos_s)?,
                r: scalar_from_buff(self.pos_r)?
            }
        })
    }
}

#[napi(object)]
pub(crate) struct SecretShareWrapper {
    pub index: u32,
    pub polynomial_evaluation: Buffer
}

impl From<SecretShare> for SecretShareWrapper {
    fn from(share: SecretShare) -> SecretShareWrapper {
        SecretShareWrapper {
            index: share.index,
            polynomial_evaluation: scalar_to_buff(share.polynomial_evaluation)
        }
    }
}

impl Into<Option<SecretShare>> for SecretShareWrapper {
    fn into(self) -> Option<SecretShare> {
        Some(SecretShare {
            index: self.index,
            polynomial_evaluation: scalar_from_buff(self.polynomial_evaluation)?
        })
    }
}

#[napi(object)]
pub(crate) struct ParticipateRes {
    pub participant: ParticipantWrapper,
    pub coefficients_handle: i64
}

#[napi(object)]
pub(crate) struct ShareRes {
    pub their_secret_shares: Vec<SecretShareWrapper>,
    pub state_handle: i64
}

#[napi(object)]
pub(crate) struct SecretKeyWrapper {
    pub index: u32,
    pub key: Buffer
}

impl From<SecretKey> for SecretKeyWrapper {
    fn from(sk: SecretKey) -> Self {
        SecretKeyWrapper {
            index: sk.index,
            key: scalar_to_buff(sk.key)
        }
    }
}

impl Into<Option<SecretKey>> for SecretKeyWrapper {
    fn into(self) -> Option<SecretKey> {
        Some(SecretKey {
            index: self.index,
            key: scalar_from_buff(self.key)?
        })
    }
}

#[napi(object)]
pub(crate) struct DeriveRes {
    pub sk: SecretKeyWrapper,
    pub pubk: PublicKeyWrapper,
    pub gk: Buffer
}

#[napi(object)]
pub struct DualRistrettoWrap {
    pub first: Buffer,
    pub second: Buffer
}

impl From<(RistrettoPoint, RistrettoPoint)> for DualRistrettoWrap {
    fn from((p1, p2): (RistrettoPoint, RistrettoPoint)) -> Self {
        Self {
            first: risteretto_point_to_buff(p1),
            second: risteretto_point_to_buff(p2)
        }
    }
}

impl Into<Option<(RistrettoPoint, RistrettoPoint)>> for DualRistrettoWrap {
    fn into(self) -> Option<(RistrettoPoint, RistrettoPoint)> {
        let first = risteretto_point_from_buff(self.first)?;
        let second = risteretto_point_from_buff(self.second)?;
        Some((first, second))
    }
}

#[napi(object)]
pub(crate) struct PubCommitmentShareListWrapper {
    pub participant_index: u32,
    pub commitment: DualRistrettoWrap 
}

impl From<PublicCommitmentShareList> for PubCommitmentShareListWrapper {
    fn from(mut pubc: PublicCommitmentShareList) -> Self {
        Self {
            participant_index: pubc.participant_index,
            commitment: pubc.commitments.remove(0).into()
        }
    }
}

impl Into<Option<PublicCommitmentShareList>> for PubCommitmentShareListWrapper {
    fn into(self) -> Option<PublicCommitmentShareList> {
        let commitment: Option<(RistrettoPoint, RistrettoPoint)> = self.commitment.into();
        Some(PublicCommitmentShareList {
            participant_index: self.participant_index,
            commitments: vec![commitment?]
        })
    }
}

#[napi(object)]
pub(crate) struct GenCommitmentShareRes {
    pub public_comm_share: PubCommitmentShareListWrapper,
    pub secret_comm_share_handle: i64
}

#[napi(object)]
pub struct SignerWrapper {
    pub participant_index: u32,
    pub published_commitment_share: DualRistrettoWrap 
}

impl From<Signer> for SignerWrapper {
    fn from(signer: Signer) -> Self {
        Self {
            participant_index: signer.participant_index,
            published_commitment_share: signer.published_commitment_share.into()
        }
    }
}

impl Into<Option<Signer>> for SignerWrapper {
    fn into(self) -> Option<Signer> {
        let published_commitment_share: Option<(RistrettoPoint, RistrettoPoint)> = self.published_commitment_share.into();
        Some(Signer {
            participant_index: self.participant_index,
            published_commitment_share: published_commitment_share?
        })
    }
}

#[napi(object)]
pub(crate) struct GenAggregatorRes {
    pub aggregator_handle: i64,
    pub signers: Vec<SignerWrapper>
}

#[napi(object)]
pub(crate) struct PartialThresholdSigWrapper {
    pub index: u32,
    pub z: Buffer
}

impl From<PartialThresholdSignature> for PartialThresholdSigWrapper {
    fn from(part: PartialThresholdSignature) -> Self {
        Self {
            index: part.index,
            z: scalar_to_buff(part.z)
        }
    }
}

impl Into<Option<PartialThresholdSignature>> for PartialThresholdSigWrapper {
    fn into(self) -> Option<PartialThresholdSignature> {
        Some(PartialThresholdSignature {
            index: self.index,
            z: scalar_from_buff(self.z)?
        })
    }
}
