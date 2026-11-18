//! Protocol-layer support modules for ShadowLemon V0.2.
//!
//! This crate hosts the session-facing helpers that sit above the frozen
//! byte-level rules in `shadowlemon-crypto`: congestion control, replay
//! protection and server-side user discovery. Handshake, session and mux
//! modules will be added by the protocol layer owner and declared here later.

#![forbid(unsafe_code)]

pub mod congestion;
pub mod driver;
pub mod handshake;
pub mod mux;
pub mod replay;
pub mod serveruser;
pub mod session;
pub mod stream;
pub mod underlay;
pub mod underlay_packet;

pub use driver::{
    ClientCredential, RealClientConfig, RealClientHandshake, RealServerConfig, RealServerHandshake,
};
pub use handshake::{
    build_registry, negotiate_suite, AeadCipher, AeadUserDecryptor, ClientHandshake,
    ClientHandshakeState, ClientOutcome, EstablishedHandshake, HandshakeError, HandshakeErrorKind,
    HandshakeTransport, ServerHandshake, ServerHandshakeResult, ServerHandshakeState,
};
pub use mux::{ClientMux, Endpoint, MuxConfig, ServerMux};
pub use session::{Direction, Session, SessionConfig, SessionError, SessionState, TransportMode};
pub use stream::DatagramStream;
pub use underlay::{Underlay, UnderlayError, UnderlayKind, UnderlayResult, WireCipher};
