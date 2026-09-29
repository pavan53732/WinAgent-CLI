pub mod capability_inspector;
pub mod path_security;
pub mod permission_inspector;
pub mod permission_judge;
pub mod permission_store;
pub mod policy;

pub use goose_providers::permission::{Permission, PermissionConfirmation};
pub mod permission_confirmation {
    pub use goose_providers::permission::PrincipalType;
}
pub use capability_inspector::CapabilityInspector;
pub use permission_inspector::PermissionInspector;
pub use permission_store::ToolPermissionStore;
pub use policy::{CapabilityPolicy, CapabilityTier, PolicyDecision};
