// Copyright 2020 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleFlag {
    Drop,
    ReturnRst,
    Fragment,
    ReturnIcmp,
    Return,
    NoSync,
    SrcTrack,
    RuleSrcTrack,
}

impl Default for RuleFlag {
    fn default() -> Self {
        RuleFlag::Drop
    }
}

impl From<RuleFlag> for u32 {
    fn from(rule_flag: RuleFlag) -> Self {
        use crate::ffi::pfvar::*;
        match rule_flag {
            RuleFlag::Drop => PFRULE_DROP as u32,
            RuleFlag::ReturnRst => PFRULE_RETURNRST as u32,
            RuleFlag::Fragment => PFRULE_FRAGMENT as u32,
            RuleFlag::ReturnIcmp => PFRULE_RETURNICMP as u32,
            RuleFlag::Return => PFRULE_RETURN as u32,
            RuleFlag::NoSync => PFRULE_NOSYNC as u32,
            RuleFlag::SrcTrack => PFRULE_SRCTRACK as u32,
            RuleFlag::RuleSrcTrack => PFRULE_RULESRCTRACK as u32,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct RuleFlagSet(Vec<RuleFlag>);

impl RuleFlagSet {
    pub fn new(set: &[RuleFlag]) -> Self {
        RuleFlagSet(set.to_vec())
    }
}

impl From<RuleFlag> for RuleFlagSet {
    fn from(rule_flag: RuleFlag) -> Self {
        RuleFlagSet(vec![rule_flag])
    }
}

impl<'a> From<&'a RuleFlagSet> for u32 {
    fn from(set: &RuleFlagSet) -> Self {
        set.0.iter().fold(0, |acc, &x| (acc | u32::from(x)))
    }
}
