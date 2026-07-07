//! agentsec-integrations: plugin adapters for external tools
//! (garak, PyRIT, Promptfoo — spec section 21).
//!
//! `plugin` implements the generic subprocess JSON protocol shared by
//! every adapter (spec 21.1-21.4). `promptfoo` is the first named
//! adapter built on top of it, scoped deliberately to just Promptfoo for
//! now — garak and PyRIT are Python-native and heavier to wrap cleanly,
//! so they're left for a follow-up rather than built speculatively
//! alongside this one.

pub mod plugin;
pub mod promptfoo;
