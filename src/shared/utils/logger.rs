use tracing_subscriber::{fmt, prelude::*};
use tracing_subscriber::{EnvFilter, Registry}; // Enables `.with()` chaining for layers

pub fn init_logger() {
    // Load RUST_LOG from environment (e.g. "debug", or "my_crate=trace")
    let env_filter = EnvFilter::from_default_env();

    // Create a formatting layer for pretty terminal logs
    let fmt_layer = fmt::layer()
        .with_target(false) // hide module path
        .with_level(true) // show log level
        // .with_thread_names(true) // thread names
        // .with_thread_ids(true) // thread IDs
        .with_line_number(true) // source line number
        .with_file(true) // source file name
        .pretty(); // pretty, colorful terminal output

    // Register everything
    Registry::default().with(env_filter).with(fmt_layer).init();
}
