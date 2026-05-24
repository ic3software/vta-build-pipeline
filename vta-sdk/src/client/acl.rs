//! ACL methods on [`VtaClient`].

use super::{
    AclEntryResponse, AclListResponse, CreateAclRequest, SwapAclRequest, UpdateAclRequest,
    VtaClient, encode_path_segment,
};
use crate::error::VtaError;

#[cfg(feature = "client")]
use crate::protocols::acl_management;

#[cfg(feature = "client")]
impl VtaClient {
    pub async fn list_acl(&self, context: Option<&str>) -> Result<AclListResponse, VtaError> {
        self.rpc(
            acl_management::LIST_ACL,
            serde_json::json!({ "context": context }),
            acl_management::LIST_ACL_RESULT,
            30,
            |c, url| {
                let mut u = format!("{url}/acl");
                if let Some(ctx) = context {
                    u.push_str(&format!("?context={ctx}"));
                }
                c.get(u)
            },
        )
        .await
    }

    pub async fn get_acl(&self, did: &str) -> Result<AclEntryResponse, VtaError> {
        self.rpc(
            acl_management::GET_ACL,
            serde_json::json!({ "did": did }),
            acl_management::GET_ACL_RESULT,
            30,
            |c, url| c.get(format!("{url}/acl/{}", encode_path_segment(did))),
        )
        .await
    }

    pub async fn create_acl(&self, req: CreateAclRequest) -> Result<AclEntryResponse, VtaError> {
        self.rpc(
            acl_management::CREATE_ACL,
            serde_json::to_value(&req)?,
            acl_management::CREATE_ACL_RESULT,
            30,
            |c, url| c.post(format!("{url}/acl")).json(&req),
        )
        .await
    }

    pub async fn update_acl(
        &self,
        did: &str,
        req: UpdateAclRequest,
    ) -> Result<AclEntryResponse, VtaError> {
        self.rpc(
            acl_management::UPDATE_ACL,
            serde_json::json!({
                "did": did,
                "role": &req.role,
                "label": &req.label,
                "allowed_contexts": &req.allowed_contexts,
            }),
            acl_management::UPDATE_ACL_RESULT,
            30,
            |c, url| {
                c.patch(format!("{url}/acl/{}", encode_path_segment(did)))
                    .json(&req)
            },
        )
        .await
    }

    pub async fn delete_acl(&self, did: &str) -> Result<(), VtaError> {
        self.rpc_void(
            acl_management::DELETE_ACL,
            serde_json::json!({ "did": did }),
            acl_management::DELETE_ACL_RESULT,
            30,
            |c, url| c.delete(format!("{url}/acl/{}", encode_path_segment(did))),
        )
        .await
    }

    /// Atomic self-service key rotation: move the caller's own ACL entry onto
    /// the DID proven by `req.presentation` (a VP-JWT). Returns the new entry.
    pub async fn swap_acl(&self, req: SwapAclRequest) -> Result<AclEntryResponse, VtaError> {
        self.rpc(
            acl_management::SWAP_ACL,
            serde_json::to_value(&req)?,
            acl_management::SWAP_ACL_RESULT,
            30,
            |c, url| c.post(format!("{url}/acl/swap")).json(&req),
        )
        .await
    }
}
