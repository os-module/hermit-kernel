use alloc::collections::btree_map::BTreeMap;

use bpf_basic::helper::RawBPFHelperFn;
use hermit_sync::Lazy;

use super::HermitKernelAux;

static EBPF_HELPER_LIST: Lazy<BTreeMap<u32, RawBPFHelperFn>> =
	Lazy::new(bpf_basic::helper::init_helper_functions::<HermitKernelAux>);

pub fn ebpf_helper_list() -> &'static BTreeMap<u32, RawBPFHelperFn> {
	&EBPF_HELPER_LIST
}
