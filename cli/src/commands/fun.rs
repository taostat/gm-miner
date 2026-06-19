//! `gmcli gm` / `gmcli moon` — the easter-egg greetings.

use crate::greeting;

/// `gmcli gm` — a tiny sunrise and the time-of-day greeting.
pub(crate) fn cmd_gm() {
    println!(
        r"        \   |   /
         .-''-.
   ---  (  ()  )  ---
         `-..-'
   ~~~~~~~~~~~~~~~~~~
   {greeting} wagmi.",
        greeting = greeting()
    );
}

/// `gmcli moon` — the quiet counterpart for the 3am deploys.
pub(crate) fn cmd_moon() {
    println!(
        r"          _.-''-._
        .'  .--.  `.
        :  (    )  :    gn. the miner runs while you sleep.
        `.  `--'  .'
          `-....-'"
    );
}
