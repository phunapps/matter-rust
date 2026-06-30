//! Matter OTA Software Update **Provider** — the controller-appropriate half of
//! OTA (Matter Core Spec §11.20, cluster `OtaSoftwareUpdateProvider` 0x0029).
//!
//! A Matter controller/admin is the actor that pushes firmware to the devices it
//! manages, so this crate implements the **Provider** role (it answers a device's
//! `QueryImage`, authorises the `ApplyUpdateRequest`, and acknowledges
//! `NotifyUpdateApplied`) — not the device-side Requestor (0x002A).
//!
//! ## Scope (phase F1)
//!
//! This crate currently holds only the **pure command-handler logic**: functions
//! that take a decoded request's command-fields TLV and produce the response
//! command-fields TLV. There is **no networking** here yet — no socket, no CASE
//! session, no BDX transfer. Those land in later F phases (`matter-bdx`,
//! operational mDNS advertising, and the decoupled provider-server task). The
//! handlers are designed to be wired by that server as:
//! `parse_invoke_request` → handler → `build_invoke_response_command`/`_status`
//! (see [`matter_interaction::invoke_server`]).
//!
//! The server direction of the 0x0029 codec (decode the inbound `QueryImage`
//! request, encode the outbound `QueryImageResponse`) is **hand-rolled here** over
//! [`matter_codec`]: the `matter-clusters` emitter only generated the *client*
//! direction (encode the request, decode the response), which this crate's tests
//! reuse as oracles.

#![forbid(unsafe_code)]

pub mod provider;

pub use provider::{
    handle_apply_update_request, handle_query_image, parse_notify_update_applied, ImageOffer,
    OtaError,
};
