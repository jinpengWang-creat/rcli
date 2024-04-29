mod cli;
mod process;
mod utils;
pub use cli::*;
use enum_dispatch::enum_dispatch;
pub use process::*;
pub use utils::*;

#[enum_dispatch]
#[allow(async_fn_in_trait)]
pub trait CmdExecutor {
    async fn execute(self) -> anyhow::Result<()>;
}
