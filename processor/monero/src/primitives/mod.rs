use monero_wallet::address::SubaddressIndex;

pub(crate) mod output;
pub(crate) mod transaction;
pub(crate) mod block;

pub(crate) const EXTERNAL_SUBADDRESS: Option<SubaddressIndex> = SubaddressIndex::new(1, 0);
pub(crate) const BRANCH_SUBADDRESS: Option<SubaddressIndex> = SubaddressIndex::new(2, 0);
pub(crate) const CHANGE_SUBADDRESS: Option<SubaddressIndex> = SubaddressIndex::new(2, 1);
pub(crate) const FORWARDED_SUBADDRESS: Option<SubaddressIndex> = SubaddressIndex::new(2, 2);
