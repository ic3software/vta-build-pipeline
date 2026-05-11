//! DID-template management methods on [`VtaClient`] (global + context scope).

use super::{VtaClient, encode_path_segment};
use crate::error::VtaError;

impl VtaClient {
    // ── DID templates (Phase 2: global scope, REST) ─────────────────────

    /// `GET /did-templates` — list all global templates.
    pub async fn list_did_templates(
        &self,
    ) -> Result<Vec<crate::did_templates::DidTemplateRecord>, VtaError> {
        use crate::protocols::did_template_management;
        #[derive(serde::Deserialize)]
        struct Wrapper {
            templates: Vec<crate::did_templates::DidTemplateRecord>,
        }
        let resp: Wrapper = self
            .rpc(
                did_template_management::LIST_TEMPLATES,
                serde_json::json!({}),
                did_template_management::LIST_TEMPLATES_RESULT,
                30,
                |c, url| c.get(format!("{url}/did-templates")),
            )
            .await?;
        Ok(resp.templates)
    }

    /// `GET /did-templates/{name}` — fetch one global template.
    pub async fn get_did_template(
        &self,
        name: &str,
    ) -> Result<crate::did_templates::DidTemplateRecord, VtaError> {
        use crate::protocols::did_template_management;
        self.rpc(
            did_template_management::GET_TEMPLATE,
            serde_json::json!({ "name": name }),
            did_template_management::GET_TEMPLATE_RESULT,
            30,
            |c, url| c.get(format!("{url}/did-templates/{}", encode_path_segment(name))),
        )
        .await
    }

    /// `POST /did-templates` — create a global template. Super admin only.
    pub async fn create_did_template(
        &self,
        template: crate::did_templates::DidTemplate,
    ) -> Result<crate::did_templates::DidTemplateRecord, VtaError> {
        use crate::protocols::did_template_management;
        self.rpc(
            did_template_management::CREATE_TEMPLATE,
            serde_json::to_value(&template)?,
            did_template_management::CREATE_TEMPLATE_RESULT,
            30,
            |c, url| c.post(format!("{url}/did-templates")).json(&template),
        )
        .await
    }

    /// `PUT /did-templates/{name}` — replace a global template. Super admin only.
    pub async fn update_did_template(
        &self,
        name: &str,
        template: crate::did_templates::DidTemplate,
    ) -> Result<crate::did_templates::DidTemplateRecord, VtaError> {
        use crate::protocols::did_template_management;
        self.rpc(
            did_template_management::UPDATE_TEMPLATE,
            serde_json::to_value(&template)?,
            did_template_management::UPDATE_TEMPLATE_RESULT,
            30,
            |c, url| {
                c.put(format!("{url}/did-templates/{}", encode_path_segment(name)))
                    .json(&template)
            },
        )
        .await
    }

    /// `DELETE /did-templates/{name}` — delete a global template. Super admin only.
    pub async fn delete_did_template(&self, name: &str) -> Result<(), VtaError> {
        use crate::protocols::did_template_management;
        self.rpc_void(
            did_template_management::DELETE_TEMPLATE,
            serde_json::json!({ "name": name }),
            did_template_management::DELETE_TEMPLATE_RESULT,
            30,
            |c, url| c.delete(format!("{url}/did-templates/{}", encode_path_segment(name))),
        )
        .await
    }

    /// `POST /did-templates/{name}/render` — render a stored template.
    ///
    /// Server injects ambient variables (`VTA_DID`, `VTA_URL`, `NOW`);
    /// `vars` provides everything else.
    pub async fn render_did_template(
        &self,
        name: &str,
        vars: std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<serde_json::Value, VtaError> {
        use crate::protocols::did_template_management;
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Req {
            vars: std::collections::HashMap<String, serde_json::Value>,
        }
        #[derive(serde::Deserialize)]
        struct Resp {
            document: serde_json::Value,
        }
        let body = Req { vars };
        let resp: Resp = self
            .rpc(
                did_template_management::RENDER_TEMPLATE,
                serde_json::to_value(&body)?,
                did_template_management::RENDER_TEMPLATE_RESULT,
                30,
                |c, url| {
                    c.post(format!(
                        "{url}/did-templates/{}/render",
                        encode_path_segment(name)
                    ))
                    .json(&body)
                },
            )
            .await?;
        Ok(resp.document)
    }

    // ── DID templates — context scope (Phase 3) ──────────────────────

    /// `GET /contexts/{id}/did-templates` — list context-scoped templates.
    pub async fn list_context_did_templates(
        &self,
        context_id: &str,
    ) -> Result<Vec<crate::did_templates::DidTemplateRecord>, VtaError> {
        use crate::protocols::did_template_management;
        #[derive(serde::Deserialize)]
        struct Wrapper {
            templates: Vec<crate::did_templates::DidTemplateRecord>,
        }
        let resp: Wrapper = self
            .rpc(
                did_template_management::LIST_TEMPLATES,
                serde_json::json!({ "context_id": context_id }),
                did_template_management::LIST_TEMPLATES_RESULT,
                30,
                |c, url| {
                    c.get(format!(
                        "{url}/contexts/{}/did-templates",
                        encode_path_segment(context_id)
                    ))
                },
            )
            .await?;
        Ok(resp.templates)
    }

    /// `GET /contexts/{id}/did-templates/{name}` — fetch one context template.
    pub async fn get_context_did_template(
        &self,
        context_id: &str,
        name: &str,
    ) -> Result<crate::did_templates::DidTemplateRecord, VtaError> {
        use crate::protocols::did_template_management;
        self.rpc(
            did_template_management::GET_TEMPLATE,
            serde_json::json!({ "context_id": context_id, "name": name }),
            did_template_management::GET_TEMPLATE_RESULT,
            30,
            |c, url| {
                c.get(format!(
                    "{url}/contexts/{}/did-templates/{}",
                    encode_path_segment(context_id),
                    encode_path_segment(name)
                ))
            },
        )
        .await
    }

    /// `POST /contexts/{id}/did-templates` — create a context-scoped template.
    /// Context admin (Admin role + context in `allowed_contexts`) or super admin.
    pub async fn create_context_did_template(
        &self,
        context_id: &str,
        template: crate::did_templates::DidTemplate,
    ) -> Result<crate::did_templates::DidTemplateRecord, VtaError> {
        use crate::protocols::did_template_management;
        self.rpc(
            did_template_management::CREATE_TEMPLATE,
            serde_json::to_value(&template)?,
            did_template_management::CREATE_TEMPLATE_RESULT,
            30,
            |c, url| {
                c.post(format!(
                    "{url}/contexts/{}/did-templates",
                    encode_path_segment(context_id)
                ))
                .json(&template)
            },
        )
        .await
    }

    /// `PUT /contexts/{id}/did-templates/{name}` — replace a context template.
    pub async fn update_context_did_template(
        &self,
        context_id: &str,
        name: &str,
        template: crate::did_templates::DidTemplate,
    ) -> Result<crate::did_templates::DidTemplateRecord, VtaError> {
        use crate::protocols::did_template_management;
        self.rpc(
            did_template_management::UPDATE_TEMPLATE,
            serde_json::to_value(&template)?,
            did_template_management::UPDATE_TEMPLATE_RESULT,
            30,
            |c, url| {
                c.put(format!(
                    "{url}/contexts/{}/did-templates/{}",
                    encode_path_segment(context_id),
                    encode_path_segment(name)
                ))
                .json(&template)
            },
        )
        .await
    }

    /// `DELETE /contexts/{id}/did-templates/{name}` — delete a context template.
    pub async fn delete_context_did_template(
        &self,
        context_id: &str,
        name: &str,
    ) -> Result<(), VtaError> {
        use crate::protocols::did_template_management;
        self.rpc_void(
            did_template_management::DELETE_TEMPLATE,
            serde_json::json!({ "context_id": context_id, "name": name }),
            did_template_management::DELETE_TEMPLATE_RESULT,
            30,
            |c, url| {
                c.delete(format!(
                    "{url}/contexts/{}/did-templates/{}",
                    encode_path_segment(context_id),
                    encode_path_segment(name)
                ))
            },
        )
        .await
    }

    /// `POST /contexts/{id}/did-templates/{name}/render` — render a context template.
    ///
    /// Server injects ambient variables: `VTA_DID`, `VTA_URL`, `NOW`,
    /// `CONTEXT_ID`, and (if set on the context) `CONTEXT_DID`.
    pub async fn render_context_did_template(
        &self,
        context_id: &str,
        name: &str,
        vars: std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<serde_json::Value, VtaError> {
        use crate::protocols::did_template_management;
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Req {
            vars: std::collections::HashMap<String, serde_json::Value>,
        }
        #[derive(serde::Deserialize)]
        struct Resp {
            document: serde_json::Value,
        }
        let body = Req { vars };
        let resp: Resp = self
            .rpc(
                did_template_management::RENDER_TEMPLATE,
                serde_json::to_value(&body)?,
                did_template_management::RENDER_TEMPLATE_RESULT,
                30,
                |c, url| {
                    c.post(format!(
                        "{url}/contexts/{}/did-templates/{}/render",
                        encode_path_segment(context_id),
                        encode_path_segment(name)
                    ))
                    .json(&body)
                },
            )
            .await?;
        Ok(resp.document)
    }
}
