//! Context methods on [`VtaClient`].

use super::{
    ContextListResponse, ContextResponse, CreateContextRequest, UpdateContextDidRequest,
    UpdateContextRequest, VtaClient, encode_path_segment,
};
use crate::error::VtaError;

#[cfg(feature = "client")]
use crate::protocols::context_management;

#[cfg(feature = "client")]
impl VtaClient {
    pub async fn list_contexts(&self) -> Result<ContextListResponse, VtaError> {
        self.rpc(
            context_management::LIST_CONTEXTS,
            serde_json::json!({}),
            context_management::LIST_CONTEXTS_RESULT,
            30,
            |c, url| c.get(format!("{url}/contexts")),
        )
        .await
    }

    pub async fn get_context(&self, id: &str) -> Result<ContextResponse, VtaError> {
        self.rpc(
            context_management::GET_CONTEXT,
            serde_json::json!({ "id": id }),
            context_management::GET_CONTEXT_RESULT,
            30,
            |c, url| c.get(format!("{url}/contexts/{}", encode_path_segment(id))),
        )
        .await
    }

    pub async fn create_context(
        &self,
        req: CreateContextRequest,
    ) -> Result<ContextResponse, VtaError> {
        self.rpc(
            context_management::CREATE_CONTEXT,
            serde_json::to_value(&req)?,
            context_management::CREATE_CONTEXT_RESULT,
            30,
            |c, url| c.post(format!("{url}/contexts")).json(&req),
        )
        .await
    }

    pub async fn update_context(
        &self,
        id: &str,
        req: UpdateContextRequest,
    ) -> Result<ContextResponse, VtaError> {
        self.rpc(
            context_management::UPDATE_CONTEXT,
            serde_json::json!({
                "id": id,
                "name": &req.name,
                "did": &req.did,
                "description": &req.description,
            }),
            context_management::UPDATE_CONTEXT_RESULT,
            30,
            |c, url| {
                c.patch(format!("{url}/contexts/{}", encode_path_segment(id)))
                    .json(&req)
            },
        )
        .await
    }

    /// Update the DID for a context. Requires Admin role with access to the context.
    pub async fn update_context_did(
        &self,
        id: &str,
        did: impl Into<String>,
    ) -> Result<ContextResponse, VtaError> {
        let did = did.into();
        self.rpc(
            context_management::UPDATE_CONTEXT_DID,
            serde_json::json!({ "id": id, "did": &did }),
            context_management::UPDATE_CONTEXT_DID_RESULT,
            30,
            |c, url| {
                c.put(format!("{url}/contexts/{}/did", encode_path_segment(id)))
                    .json(&UpdateContextDidRequest { did: did.clone() })
            },
        )
        .await
    }

    pub async fn preview_delete_context(
        &self,
        id: &str,
    ) -> Result<context_management::delete::DeleteContextPreviewResultBody, VtaError> {
        self.rpc(
            context_management::PREVIEW_DELETE_CONTEXT,
            serde_json::json!({ "id": id }),
            context_management::PREVIEW_DELETE_CONTEXT_RESULT,
            30,
            |c, url| {
                c.get(format!(
                    "{url}/contexts/{}/delete-preview",
                    encode_path_segment(id)
                ))
            },
        )
        .await
    }

    pub async fn delete_context(&self, id: &str, force: bool) -> Result<(), VtaError> {
        self.rpc_void(
            context_management::DELETE_CONTEXT,
            serde_json::json!({ "id": id, "force": force }),
            context_management::DELETE_CONTEXT_RESULT,
            30,
            |c, url| {
                let mut url = format!("{url}/contexts/{}", encode_path_segment(id));
                if force {
                    url.push_str("?force=true");
                }
                c.delete(url)
            },
        )
        .await
    }
}
