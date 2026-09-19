use clap::{Args, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ApiMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Debug, Args)]
pub struct ApiArgs {
    /// API path relative to the platform's network prefix.
    /// Integration paths use API-key auth; other paths use Session auth.
    ///
    /// Session style:  api/s/{site}/stat/sitedpi
    /// V2 style:      v2/api/site/{site}/traffic-flow-latest-statistics
    /// Integration:   integration/v1/dpi/applications
    pub path: String,

    /// HTTP method
    #[arg(long, short, value_enum, default_value_t = ApiMethod::Get)]
    pub method: ApiMethod,

    /// JSON request body (for POST, PUT, or PATCH)
    #[arg(long, short)]
    pub data: Option<String>,
}
