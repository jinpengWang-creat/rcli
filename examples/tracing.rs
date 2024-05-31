use std::{thread, time::Duration};

use tracing::{instrument, Level};

fn main() {
    let span = tracing::span!(Level::INFO, "my_span");

    let _enter = span.enter();
}

#[instrument]
fn my_function() {
    thread::sleep(Duration::from_secs(2));
    println!("my_function");
}
