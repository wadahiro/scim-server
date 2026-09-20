//! Generated-check families keyed off data that lives outside the
//! schema-driven matrix (`crate::matrix`) and the RFC 7644 §3.5.2
//! requirement ledger (`crate::requirement`, `crate::templates`).
//!
//! Today, just [`attrdefs`] (T9): the RFC 7643 §5/§6/§7 and RFC 7644
//! §3.4.2 "REQUIRED member" tables, checked against the server's fixed
//! discovery endpoints.

pub mod attrdef_scan;
pub mod attrdefs;
