use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    User,
    Group,
}

impl ResourceType {
}

impl fmt::Display for ResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceType::User => write!(f, "User"),
            ResourceType::Group => write!(f, "Group"),
        }
    }
}