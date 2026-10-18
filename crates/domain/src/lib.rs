pub mod allow_list;
pub mod error;

/// Write only what differs (weebo-si RFC 0003): the kit's drift helpers.
pub use weebo_kit_domain::drift;
pub use weebo_kit_domain::{Drift, RemoteWrite};
