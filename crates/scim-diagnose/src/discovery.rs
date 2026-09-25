//! The `discovery_presence` family: 38 static axes checking which members
//! a discovery endpoint's response must, may, or (for three of them)
//! conditionally-must contain, per RFC 7643's `ServiceProviderConfig`
//! (§5), `ResourceType` (§6), and `Schema` (§7) required-member
//! definitions, plus RFC 7644 §3.4.2's `ListResponse` envelope. Ported
//! from `feat/rfc-extract`'s `crates/scim-conformance/src/gen/
//! {attrdefs.rs,attrdef_scan.rs}` and `golden/attrdefs.json` (61 scraped
//! attribute-definition-table entries, of which 38 name a `(rfc, section)`
//! mapping to one of these four discovery endpoints).
//!
//! ## Data-file decision
//!
//! The source branch carried the 61 entries as a 24 KB generated JSON
//! fixture (`golden/attrdefs.json`) plus a 234-line scanner
//! (`attrdef_scan.rs`) that re-derived each entry's RFC line span from the
//! vendored text at every test run, and a 415-line generator
//! (`attrdefs.rs`) that cross-checked the JSON against the scanner's own
//! output. This crate hand-writes the 38 matched entries as typed `Basis`
//! constants in `crate::rfc` instead (`DISCOVERY_{SPC,RT,SCHEMA,LIST}_*`)
//! and a plain Rust table here, and does not carry the JSON or the scanner
//! across. Reasoning: the data is small (38 rows), fixed (RFC 7643/7644 are
//! frozen documents -- these tables will never change under us the way a
//! target's own `/Schemas` can), and every existing citation in
//! `crate::rfc` is already a hand-written, `sed`-verified constant, not a
//! generated fixture -- carrying a JSON+scanner pair across would be the
//! only generated-data path in a crate whose entire citation discipline is
//! "type it, verify it against the vendored text, and never regenerate
//! it". The 38 constants get exactly the same verification the JSON+scanner
//! pair gave the source branch (`crate::rfc::quote_tests::verify_quotes`,
//! extended to cover these), with substantially less code and no
//! runtime-parsed data file inside the shipped binary.
//!
//! ## `Mandated` vs. `SelfDeclared`
//!
//! Every one of the 26 non-conditional `REQUIRED` entries here is modeled
//! `RfcPosition::Mandated` (`Keyword::Must`), not `RfcPosition::SelfDeclared`
//! -- even though this server's own `/Schemas` happens to publish a
//! `ServiceProviderConfig` schema entry that independently declares
//! `patch.supported` (and its siblings) `required: true`
//! (`src/resource/schema.rs`), which is the same shape of evidence that
//! makes `user_groups_presence` (`crate::axes`) a `SelfDeclared` axis.
//! `SelfDeclared` fits `user_groups_presence` because RFC 7643 §7's
//! `returned` characteristic genuinely leaves the *choice* of value
//! (`never`/`default`/`always`/`request`) to the provider -- the RFC
//! defines what each value *means* but never says which one applies to
//! `User.groups`; the obligation only exists once the target's own
//! `/Schemas` picks one, and a different, equally RFC-legal target could
//! pick differently. These 38 checks have no such choice: RFC 7643
//! §5/§6/§7 and RFC 7644 §3.4.2 name the cardinality of
//! `patch.supported` (etc.) directly and identically for every conformant
//! provider -- there is no RFC-legal alternative under which a
//! `ServiceProviderConfig` may omit `patch.supported`. A provider's own
//! `/Schemas` entry for these meta-schemas, when present, is *corroborating*
//! evidence of what the RFC already mandates, not the *source* of the
//! obligation the way `returned` is -- so treating these as `SelfDeclared`
//! would mean the wrong text carries the citation (the target's own
//! declaration, rather than the RFC passage that actually says
//! "REQUIRED"), and picking `Mandated` avoids the cost of generalising
//! `rfc::self_declared_is_fault` (currently hardcoded to the
//! `declares_{never,default}_{present,absent}` token shape the `returned`
//! characteristic uses) for a family that does not need that shape at all.
//!
//! ## `ABSENT_PARENT` / conditionally-required entries
//!
//! Ported from the source branch's three-valued `Presence` enum
//! (`Ok`/`Missing`/`AbsentParent` in `attrdefs.rs`): a `REQUIRED` child
//! whose immediate JSON parent is itself absent (e.g.
//! `schemaExtensions.schema`/`.required` when `schemaExtensions` -- itself
//! `OPTIONAL` -- is omitted entirely) is not evidence the child was
//! omitted in violation of its own requirement; there was no parent object
//! to carry it. Modeled here as `Value::Unobservable(Unobservable::
//! ProbeFailed(_))` rather than a third named `Value::Known` token: the
//! generic fault predicate `crate::render::is_fault` judges a `Mandated`
//! axis purely by comparing the observed token against `expected` (see its
//! doc comment), so a `Value::Known("absent_parent")` would need that
//! predicate widened axis-by-axis to know a non-`"present"` token still
//! isn't a fault -- the same generalisation cost flagged above for
//! `SelfDeclared`, paid here for no reason, since `Unobservable` already
//! short-circuits `is_fault` to `None` ("n/a") for exactly this "ran, but
//! there was nothing to judge" case.
//!
//! The three conditionally-`REQUIRED` `ListResponse` entries (`Resources`,
//! `startIndex`, `itemsPerPage`) get the same `Unobservable::ProbeFailed`
//! treatment unconditionally, naming the RFC's own gating text (see
//! [`run`]) -- matching the source branch, whose `attrdefs.rs` also never
//! evaluated a conditional entry's condition against the fetched response
//! (every `conditional: true` golden entry there is an unconditional
//! `Verdict::Skip`). This crate does not attempt to determine whether
//! `totalResults` is non-zero or the response is genuinely a paginated,
//! partial page and judge presence against that -- deciding that
//! correctly (in particular, when a "partial results due to pagination"
//! condition really holds for an arbitrary third-party target) is exactly
//! the kind of judgment call this family's brief did not ask for, and
//! getting it wrong would turn a should-be-`Unobservable` instance into a
//! false `VIOLATION`. Note for the record: this server (`src/resource/
//! user.rs`) always sends `startIndex`/`itemsPerPage` regardless of
//! whether pagination actually applies, so all three entries are in fact
//! always present in its own responses -- the `Unobservable` classification
//! here is this family's policy choice not to judge the conditional case,
//! not evidence one way or the other about this server specifically.
//!
//! ## Cost
//!
//! Every instance is `Cost::DiscoveryOnly`: four `GET`s total
//! (`/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`,
//! `/Users?count=1`), cached and shared across all 38 checks by [`run`]
//! rather than one fetch per axis. `/Users?count=1` is a plain read against
//! whatever data already exists on the target (possibly zero Users) --
//! never a fixture creation -- so the three `ListResponse` entries belong
//! in the default (discovery-only, no `--allow-writes`) budget exactly like
//! the other 35, even though they inspect a `/Users` response.
//!
//! ## Integration shape
//!
//! Unlike `crate::matrix::derive`/`crate::matrix::projection`, this
//! family's instance set is *not* derived from the target's own `GET
//! /Schemas` or `GET /ResourceTypes` -- RFC 7643/7644 fix all 38
//! `(endpoint, attribute path)` pairs at the text level, so there is
//! nothing target-specific to expand over. [`DISCOVERY_AXES`] is therefore
//! a plain `&'static [Axis]` table, the same shape as `crate::axes::AXES`'s
//! 32 static axes, rather than a `DerivedFamily`/`ProjectionAxis`-style
//! generator -- `crate::render::axis_for` looks it up alongside `AXES`
//! (see its call site) so the 38 checks print individually in the human
//! text view exactly like the existing 32, instead of needing a new
//! aggregation section the way the 389-instance schema-derived matrix and
//! the 16-instance `attribute_projection` family do (neither of which
//! could reasonably print one line per instance). A parallel `ENTRIES`
//! table (endpoint/shape/path/condition, not part of the public `Axis`
//! shape) drives [`run`]'s actual HTTP probing.

use serde_json::Value as Json;

use crate::axis::{Axis, Cost, Observation, Unobservable, Value};
use crate::client::{truncate, ScimClient};
use crate::fixtures::{body_of, is_2xx, safe};
use crate::rfc::{self, Keyword, RfcPosition};

pub const FAMILY_ID: &str = "discovery_presence";

/// The only two tokens a `Value::Known` observation ever carries for this
/// family -- `absent_parent` and "condition not met" are `Unobservable`
/// instead (see this module's doc comment), never a third `Known` token.
const KNOWN: &[&str] = &["present", "absent"];

/// `pub`: `crate::render`'s aggregated views reuse this predicate rather
/// than reimplementing it, matching `crate::matrix::projection::
/// is_fault_token`'s convention.
pub fn is_fault_token(v: &str) -> bool {
    v == "absent"
}

/// Which discovery endpoint an entry's `path` is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    ServiceProviderConfig,
    ResourceTypes,
    Schemas,
    ListResponse,
}

impl Endpoint {
    fn request_path(&self) -> &'static str {
        match self {
            Endpoint::ServiceProviderConfig => "/ServiceProviderConfig",
            Endpoint::ResourceTypes => "/ResourceTypes",
            Endpoint::Schemas => "/Schemas",
            Endpoint::ListResponse => "/Users",
        }
    }

    /// `ResourceTypes`/`Schemas` responses are `ListResponse`s whose
    /// `Resources[]` array is what RFC 7643 §6/§7's tables actually
    /// describe (each element is one `ResourceType`/`Schema`); every
    /// element must carry a `REQUIRED` member for the check to pass.
    /// `ServiceProviderConfig` is a single resource, and
    /// `/Users?count=1`'s own `ListResponse` envelope (RFC 7644 §3.4.2)
    /// is itself the thing being checked, not something to unwrap one
    /// level further.
    fn shape(&self) -> Shape {
        match self {
            Endpoint::ServiceProviderConfig | Endpoint::ListResponse => Shape::Single,
            Endpoint::ResourceTypes | Endpoint::Schemas => Shape::List,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Single,
    List,
}

/// One (endpoint, attribute path) check -- the runtime counterpart to a
/// [`DISCOVERY_AXES`] entry, matched to it by `id`. `condition`, when
/// `Some`, names the RFC's own gating text for the three conditionally-
/// `REQUIRED` `ListResponse` entries (`Resources`, `startIndex`,
/// `itemsPerPage`); see this module's doc comment for why it is recorded
/// but not evaluated against the fetched response.
struct DiscoveryEntry {
    id: &'static str,
    endpoint: Endpoint,
    path: &'static str,
    condition: Option<&'static str>,
}

pub const DISCOVERY_AXES: &[Axis] = &[
    Axis {
        id: "discovery_presence/ServiceProviderConfig.documentationUri",
        about: "whether 'documentationUri' is present in ServiceProviderConfig",
        rfc: RfcPosition::Permitted {
            basis: rfc::DISCOVERY_SPC_DOCUMENTATION_URI,
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.patch",
        about: "whether 'patch' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_PATCH,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.patch.supported",
        about: "whether 'patch.supported' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_PATCH_SUPPORTED,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.bulk",
        about: "whether 'bulk' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_BULK,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.bulk.supported",
        about: "whether 'bulk.supported' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_BULK_SUPPORTED,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.bulk.maxOperations",
        about: "whether 'bulk.maxOperations' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_BULK_MAX_OPERATIONS,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.bulk.maxPayloadSize",
        about: "whether 'bulk.maxPayloadSize' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_BULK_MAX_PAYLOAD_SIZE,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.filter",
        about: "whether 'filter' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_FILTER,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.filter.supported",
        about: "whether 'filter.supported' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_FILTER_SUPPORTED,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.filter.maxResults",
        about: "whether 'filter.maxResults' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_FILTER_MAX_RESULTS,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.changePassword",
        about: "whether 'changePassword' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_CHANGE_PASSWORD,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.changePassword.supported",
        about: "whether 'changePassword.supported' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_CHANGE_PASSWORD_SUPPORTED,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.sort",
        about: "whether 'sort' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_SORT,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.sort.supported",
        about: "whether 'sort.supported' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_SORT_SUPPORTED,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.etag",
        about: "whether 'etag' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_ETAG,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.etag.supported",
        about: "whether 'etag.supported' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_ETAG_SUPPORTED,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.authenticationSchemes",
        about: "whether 'authenticationSchemes' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_AUTHENTICATION_SCHEMES,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.authenticationSchemes.type",
        about: "whether 'authenticationSchemes.type' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_AUTHENTICATION_SCHEMES_TYPE,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.authenticationSchemes.name",
        about: "whether 'authenticationSchemes.name' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_AUTHENTICATION_SCHEMES_NAME,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.authenticationSchemes.description",
        about: "whether 'authenticationSchemes.description' is present in ServiceProviderConfig",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SPC_AUTHENTICATION_SCHEMES_DESCRIPTION,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.authenticationSchemes.specUri",
        about: "whether 'authenticationSchemes.specUri' is present in ServiceProviderConfig",
        rfc: RfcPosition::Permitted {
            basis: rfc::DISCOVERY_SPC_AUTHENTICATION_SCHEMES_SPEC_URI,
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ServiceProviderConfig.authenticationSchemes.documentationUri",
        about:
            "whether 'authenticationSchemes.documentationUri' is present in ServiceProviderConfig",
        rfc: RfcPosition::Permitted {
            basis: rfc::DISCOVERY_SPC_AUTHENTICATION_SCHEMES_DOCUMENTATION_URI,
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ResourceTypes.id",
        about: "whether 'id' is present in ResourceTypes",
        rfc: RfcPosition::Permitted {
            basis: rfc::DISCOVERY_RT_ID,
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ResourceTypes.name",
        about: "whether 'name' is present in ResourceTypes",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_RT_NAME,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ResourceTypes.description",
        about: "whether 'description' is present in ResourceTypes",
        rfc: RfcPosition::Permitted {
            basis: rfc::DISCOVERY_RT_DESCRIPTION,
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ResourceTypes.endpoint",
        about: "whether 'endpoint' is present in ResourceTypes",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_RT_ENDPOINT,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ResourceTypes.schema",
        about: "whether 'schema' is present in ResourceTypes",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_RT_SCHEMA,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ResourceTypes.schemaExtensions",
        about: "whether 'schemaExtensions' is present in ResourceTypes",
        rfc: RfcPosition::Permitted {
            basis: rfc::DISCOVERY_RT_SCHEMA_EXTENSIONS,
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ResourceTypes.schemaExtensions.schema",
        about: "whether 'schemaExtensions.schema' is present in ResourceTypes",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_RT_SCHEMA_EXTENSIONS_SCHEMA,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ResourceTypes.schemaExtensions.required",
        about: "whether 'schemaExtensions.required' is present in ResourceTypes",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_RT_SCHEMA_EXTENSIONS_REQUIRED,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/Schemas.id",
        about: "whether 'id' is present in Schemas",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_SCHEMA_ID,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/Schemas.name",
        about: "whether 'name' is present in Schemas",
        rfc: RfcPosition::Permitted {
            basis: rfc::DISCOVERY_SCHEMA_NAME,
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/Schemas.description",
        about: "whether 'description' is present in Schemas",
        rfc: RfcPosition::Permitted {
            basis: rfc::DISCOVERY_SCHEMA_DESCRIPTION,
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/Schemas.attributes.canonicalValues",
        about: "whether 'attributes.canonicalValues' is present in Schemas",
        rfc: RfcPosition::Permitted {
            basis: rfc::DISCOVERY_SCHEMA_ATTRIBUTES_CANONICAL_VALUES,
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ListResponse.totalResults",
        about: "whether 'totalResults' is present in ListResponse",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_LIST_TOTAL_RESULTS,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ListResponse.Resources",
        about: "whether 'Resources' is present in ListResponse",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_LIST_RESOURCES,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ListResponse.startIndex",
        about: "whether 'startIndex' is present in ListResponse",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_LIST_START_INDEX,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
    Axis {
        id: "discovery_presence/ListResponse.itemsPerPage",
        about: "whether 'itemsPerPage' is present in ListResponse",
        rfc: RfcPosition::Mandated {
            basis: rfc::DISCOVERY_LIST_ITEMS_PER_PAGE,
            keyword: Keyword::Must,
            expected: "present",
        },
        knob: None,
        cost: Cost::DiscoveryOnly,
        known: KNOWN,
    },
];

const ENTRIES: &[DiscoveryEntry] = &[
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.documentationUri",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "documentationUri",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.patch",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "patch",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.patch.supported",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "patch.supported",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.bulk",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "bulk",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.bulk.supported",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "bulk.supported",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.bulk.maxOperations",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "bulk.maxOperations",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.bulk.maxPayloadSize",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "bulk.maxPayloadSize",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.filter",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "filter",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.filter.supported",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "filter.supported",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.filter.maxResults",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "filter.maxResults",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.changePassword",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "changePassword",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.changePassword.supported",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "changePassword.supported",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.sort",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "sort",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.sort.supported",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "sort.supported",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.etag",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "etag",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.etag.supported",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "etag.supported",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.authenticationSchemes",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "authenticationSchemes",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.authenticationSchemes.type",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "authenticationSchemes.type",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.authenticationSchemes.name",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "authenticationSchemes.name",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.authenticationSchemes.description",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "authenticationSchemes.description",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.authenticationSchemes.specUri",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "authenticationSchemes.specUri",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ServiceProviderConfig.authenticationSchemes.documentationUri",
        endpoint: Endpoint::ServiceProviderConfig,
        path: "authenticationSchemes.documentationUri",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ResourceTypes.id",
        endpoint: Endpoint::ResourceTypes,
        path: "id",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ResourceTypes.name",
        endpoint: Endpoint::ResourceTypes,
        path: "name",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ResourceTypes.description",
        endpoint: Endpoint::ResourceTypes,
        path: "description",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ResourceTypes.endpoint",
        endpoint: Endpoint::ResourceTypes,
        path: "endpoint",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ResourceTypes.schema",
        endpoint: Endpoint::ResourceTypes,
        path: "schema",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ResourceTypes.schemaExtensions",
        endpoint: Endpoint::ResourceTypes,
        path: "schemaExtensions",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ResourceTypes.schemaExtensions.schema",
        endpoint: Endpoint::ResourceTypes,
        path: "schemaExtensions.schema",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ResourceTypes.schemaExtensions.required",
        endpoint: Endpoint::ResourceTypes,
        path: "schemaExtensions.required",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/Schemas.id",
        endpoint: Endpoint::Schemas,
        path: "id",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/Schemas.name",
        endpoint: Endpoint::Schemas,
        path: "name",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/Schemas.description",
        endpoint: Endpoint::Schemas,
        path: "description",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/Schemas.attributes.canonicalValues",
        endpoint: Endpoint::Schemas,
        path: "attributes.canonicalValues",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ListResponse.totalResults",
        endpoint: Endpoint::ListResponse,
        path: "totalResults",
        condition: None,
    },
    DiscoveryEntry {
        id: "discovery_presence/ListResponse.Resources",
        endpoint: Endpoint::ListResponse,
        path: "Resources",
        condition: Some("REQUIRED if \"totalResults\" is non-zero"),
    },
    DiscoveryEntry {
        id: "discovery_presence/ListResponse.startIndex",
        endpoint: Endpoint::ListResponse,
        path: "startIndex",
        condition: Some("REQUIRED when partial results are returned due to pagination"),
    },
    DiscoveryEntry {
        id: "discovery_presence/ListResponse.itemsPerPage",
        endpoint: Endpoint::ListResponse,
        path: "itemsPerPage",
        condition: Some("REQUIRED when partial results are returned due to pagination"),
    },
];

// ------------------------------------------------------------- presence walk

/// Tri-state presence classification, ported from `feat/rfc-extract`'s
/// `attrdefs.rs::Presence` (`Ok`/`Missing`/`AbsentParent`), renamed here to
/// match this crate's `Value`/`Unobservable` vocabulary rather than that
/// branch's pass/fail `Verdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    AbsentParent,
    Missing,
    Ok,
}

/// Walks `dotted` (e.g. `"authenticationSchemes.type"`) through `obj`. If a
/// traversed segment's value is an array, every element of it must carry
/// the next segment -- i.e. if the path passes through an array, presence
/// is required in every element. Ported near-verbatim from
/// `feat/rfc-extract`'s `attrdefs.rs::present`.
fn present(obj: &Json, dotted: &str) -> Presence {
    let parts: Vec<&str> = dotted.split('.').collect();
    let mut cur: Vec<&Json> = vec![obj];
    for part in &parts[..parts.len() - 1] {
        let mut next: Vec<&Json> = Vec::new();
        for c in &cur {
            let Some(map) = c.as_object() else {
                return Presence::AbsentParent;
            };
            let Some(v) = map.get(*part) else {
                return Presence::AbsentParent;
            };
            match v {
                Json::Array(items) => next.extend(items.iter()),
                other => next.push(other),
            }
        }
        if next.is_empty() {
            return Presence::AbsentParent; // empty array: no element to ask
        }
        cur = next;
    }
    let last = parts[parts.len() - 1];
    for c in &cur {
        match c.as_object() {
            Some(map) if map.contains_key(last) => {}
            _ => return Presence::Missing,
        }
    }
    Presence::Ok
}

/// Aggregates one [`Presence`] per `Resources[]` element (`Shape::List`) --
/// ported from `feat/rfc-extract`'s `attrdefs.rs::verdict_for`, adapted
/// from that function's `(Verdict, String)` return to this crate's
/// `(Presence, String)` (the caller turns the aggregate `Presence` into an
/// `Observation` the same way a single-element check does). Any element
/// `Missing` aggregates to `Missing` (a fault, if `Mandated`); every
/// element `AbsentParent` aggregates to `AbsentParent`; a mix of
/// `AbsentParent` and `Ok` (no `Missing`) aggregates to `Ok`, noting how
/// many elements were excluded.
fn aggregate(results: &[Presence], attr: &str) -> (Presence, String) {
    let missing = results.iter().filter(|p| **p == Presence::Missing).count();
    let absent_parent = results
        .iter()
        .filter(|p| **p == Presence::AbsentParent)
        .count();
    if missing > 0 {
        return (
            Presence::Missing,
            format!(
                "\"{attr}\" missing in {missing} of {} element(s)",
                results.len()
            ),
        );
    }
    if absent_parent == results.len() {
        return (
            Presence::AbsentParent,
            format!("\"{attr}\"'s parent is absent in every element"),
        );
    }
    if absent_parent > 0 {
        return (
            Presence::Ok,
            format!(
                "\"{attr}\" present in all {} element(s) with the parent present ({absent_parent} \
                 excluded -- parent absent)",
                results.len() - absent_parent
            ),
        );
    }
    (
        Presence::Ok,
        format!("\"{attr}\" present in all {} element(s)", results.len()),
    )
}

fn judge_presence(entry: &DiscoveryEntry, body: &Json) -> (Presence, String) {
    match entry.endpoint.shape() {
        Shape::Single => {
            let p = present(body, entry.path);
            let detail = match p {
                Presence::Ok => format!("\"{}\" present", entry.path),
                Presence::Missing => format!("\"{}\" missing", entry.path),
                Presence::AbsentParent => {
                    format!("\"{}\"'s parent is absent from the response", entry.path)
                }
            };
            (p, detail)
        }
        Shape::List => {
            let items: Vec<&Json> = body
                .get("Resources")
                .and_then(Json::as_array)
                .map(|a| a.iter().collect())
                .unwrap_or_default();
            if items.is_empty() {
                return (
                    Presence::AbsentParent,
                    format!(
                        "GET {} returned no Resources; nothing to check \"{}\" against",
                        entry.endpoint.request_path(),
                        entry.path
                    ),
                );
            }
            let results: Vec<Presence> = items.iter().map(|it| present(it, entry.path)).collect();
            aggregate(&results, entry.path)
        }
    }
}

/// `Presence::Ok`/`Missing` become `Value::Known("present"/"absent")`;
/// `Presence::AbsentParent` becomes `Unobservable::ProbeFailed` (see this
/// module's doc comment for why, over a third `Known` token).
fn observation_for_presence(
    id: &str,
    presence: Presence,
    detail: String,
    exchange: crate::client::Exchange,
) -> Observation {
    match presence {
        Presence::Ok => Observation {
            axis: id.to_string(),
            value: Value::Known("present"),
            evidence: vec![exchange],
            detail,
        },
        Presence::Missing => Observation {
            axis: id.to_string(),
            value: Value::Known("absent"),
            evidence: vec![exchange],
            detail,
        },
        Presence::AbsentParent => Observation {
            axis: id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(detail)),
            evidence: vec![exchange],
            detail: String::new(),
        },
    }
}

// ------------------------------------------------------------------- run

/// Fetches the four discovery endpoints once each and judges all 38
/// [`ENTRIES`] against the cached responses, matching each entry to its
/// [`DISCOVERY_AXES`] counterpart by `id`. A fetch that fails outright (non
/// -2xx or transport error) makes every entry against that endpoint
/// `Unobservable::ProbeFailed`, not a silent omission.
pub async fn run(client: &ScimClient) -> Vec<Observation> {
    let spc = safe(client.get(Endpoint::ServiceProviderConfig.request_path())).await;
    let rt = safe(client.get(Endpoint::ResourceTypes.request_path())).await;
    let schemas = safe(client.get(Endpoint::Schemas.request_path())).await;
    let list =
        safe(client.get_query(Endpoint::ListResponse.request_path(), &[("count", "1")])).await;

    let mut out = Vec::with_capacity(ENTRIES.len());
    for entry in ENTRIES {
        let r = match entry.endpoint {
            Endpoint::ServiceProviderConfig => &spc,
            Endpoint::ResourceTypes => &rt,
            Endpoint::Schemas => &schemas,
            Endpoint::ListResponse => &list,
        };
        if !is_2xx(r.status) {
            out.push(Observation {
                axis: entry.id.to_string(),
                value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                    "GET {} -> status={} body={}",
                    entry.endpoint.request_path(),
                    r.status,
                    truncate(&r.raw, 150)
                ))),
                evidence: vec![r.exchange.clone()],
                detail: String::new(),
            });
            continue;
        }
        let body = body_of(r);

        // Conditional-REQUIRED entries (`Resources`, `startIndex`,
        // `itemsPerPage`): the RFC's obligation only bites when its own
        // gating condition holds (`totalResults` non-zero; a paginated,
        // partial result set), and this family does not attempt to
        // evaluate that condition against the fetched response -- the
        // source branch's `attrdefs.rs` didn't either (every conditional
        // entry there is an unconditional `Verdict::Skip`, never fetched
        // against). Recorded as `Unobservable::ProbeFailed` naming the
        // RFC's own condition text, the same "not a pass, not a fail"
        // treatment `ABSENT_PARENT` gets below, and for the same reason:
        // without evaluating the gate, presence or absence here proves
        // nothing about whether the requirement was actually violated.
        if let Some(condition) = entry.condition {
            out.push(Observation {
                axis: entry.id.to_string(),
                value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                    "conditionally required, not evaluated: \"{}\" is {condition} (RFC 7644 \
                     §3.4.2); this family checks unconditional presence only",
                    entry.path
                ))),
                evidence: vec![r.exchange.clone()],
                detail: String::new(),
            });
            continue;
        }

        let (presence, detail) = judge_presence(entry, &body);
        out.push(observation_for_presence(
            entry.id,
            presence,
            detail,
            r.exchange.clone(),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn axes_and_entries_have_matching_ids_in_order() {
        assert_eq!(DISCOVERY_AXES.len(), 38);
        assert_eq!(ENTRIES.len(), 38);
        for (axis, entry) in DISCOVERY_AXES.iter().zip(ENTRIES.iter()) {
            assert_eq!(axis.id, entry.id);
        }
    }

    #[test]
    fn ids_are_unique() {
        let mut ids: Vec<&str> = DISCOVERY_AXES.iter().map(|a| a.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 38);
    }

    #[test]
    fn present_required_field_missing_is_missing() {
        let obj = json!({"schemas": ["x"]});
        assert_eq!(present(&obj, "totalResults"), Presence::Missing);
    }

    #[test]
    fn present_optional_parent_absent_is_absent_parent() {
        let obj = json!({"patch": {}});
        assert_eq!(present(&obj, "bulk.supported"), Presence::AbsentParent);
    }

    #[test]
    fn present_optional_parent_absent_via_empty_array_is_absent_parent() {
        let obj = json!({"authenticationSchemes": []});
        assert_eq!(
            present(&obj, "authenticationSchemes.type"),
            Presence::AbsentParent
        );
    }

    #[test]
    fn present_everything_present_is_ok() {
        let obj = json!({"bulk": {"supported": true, "maxOperations": 1, "maxPayloadSize": 1}});
        assert_eq!(present(&obj, "bulk.supported"), Presence::Ok);
        assert_eq!(present(&obj, "bulk"), Presence::Ok);
    }

    #[test]
    fn present_array_parent_requires_every_element_to_carry_the_child() {
        let ok = json!({
            "authenticationSchemes": [
                {"type": "oauthbearertoken"},
                {"type": "httpbasic"}
            ]
        });
        assert_eq!(present(&ok, "authenticationSchemes.type"), Presence::Ok);

        let partial = json!({
            "authenticationSchemes": [
                {"type": "oauthbearertoken"},
                {"other": "x"}
            ]
        });
        assert_eq!(
            present(&partial, "authenticationSchemes.type"),
            Presence::Missing
        );
    }

    #[test]
    fn aggregate_required_missing_in_some_elements_fails() {
        let (p, _) = aggregate(&[Presence::Ok, Presence::Missing], "attr");
        assert_eq!(p, Presence::Missing);
    }

    #[test]
    fn aggregate_absent_parent_in_every_element_is_absent_parent() {
        let (p, _) = aggregate(&[Presence::AbsentParent, Presence::AbsentParent], "attr");
        assert_eq!(p, Presence::AbsentParent);
    }

    #[test]
    fn aggregate_mixed_absent_parent_and_ok_is_ok() {
        let (p, _) = aggregate(&[Presence::AbsentParent, Presence::Ok], "attr");
        assert_eq!(p, Presence::Ok);
    }

    #[test]
    fn is_fault_token_only_flags_absent() {
        assert!(is_fault_token("absent"));
        assert!(!is_fault_token("present"));
    }

    #[test]
    fn every_axis_is_discovery_only_with_no_knob() {
        for axis in DISCOVERY_AXES {
            assert_eq!(
                axis.cost,
                Cost::DiscoveryOnly,
                "{} must be DiscoveryOnly",
                axis.id
            );
            assert!(axis.knob.is_none(), "{} must have no knob", axis.id);
        }
    }

    #[test]
    fn required_non_conditional_entries_are_mandated_must() {
        let conditional_ids = [
            "discovery_presence/ListResponse.Resources",
            "discovery_presence/ListResponse.startIndex",
            "discovery_presence/ListResponse.itemsPerPage",
        ];
        let mandated_count = DISCOVERY_AXES
            .iter()
            .filter(|a| {
                matches!(
                    a.rfc,
                    RfcPosition::Mandated {
                        keyword: Keyword::Must,
                        expected: "present",
                        ..
                    }
                )
            })
            .count();
        // 26 non-conditional REQUIRED + 3 conditional REQUIRED = 29.
        assert_eq!(mandated_count, 29);
        for id in conditional_ids {
            let axis = DISCOVERY_AXES.iter().find(|a| a.id == id).unwrap();
            assert!(matches!(axis.rfc, RfcPosition::Mandated { .. }));
        }
    }

    #[test]
    fn optional_entries_are_permitted() {
        let permitted_count = DISCOVERY_AXES
            .iter()
            .filter(|a| matches!(a.rfc, RfcPosition::Permitted { .. }))
            .count();
        assert_eq!(permitted_count, 9);
    }
}
