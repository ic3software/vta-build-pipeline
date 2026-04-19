//! Protocol constants for DID template management.
//!
//! Phase 2 carries these over REST only. The constants are in place so a
//! future DIDComm path can slot in without a naming change.

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/did-template-management/1.0";

pub const LIST_TEMPLATES: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/list-templates";
pub const LIST_TEMPLATES_RESULT: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/list-templates-result";

pub const GET_TEMPLATE: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/get-template";
pub const GET_TEMPLATE_RESULT: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/get-template-result";

pub const CREATE_TEMPLATE: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/create-template";
pub const CREATE_TEMPLATE_RESULT: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/create-template-result";

pub const UPDATE_TEMPLATE: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/update-template";
pub const UPDATE_TEMPLATE_RESULT: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/update-template-result";

pub const DELETE_TEMPLATE: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/delete-template";
pub const DELETE_TEMPLATE_RESULT: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/delete-template-result";

pub const RENDER_TEMPLATE: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/render-template";
pub const RENDER_TEMPLATE_RESULT: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/render-template-result";
