use core::ops::{Deref, DerefMut};

use memory_addresses::{PhysAddr, VirtAddr};
use x86_64::structures::paging::PageTableFlags;

use crate::arch::mm::paging::{BasePageSize, PageTableEntryFlagsExt};

pub struct JITMem {
	virt_addr: VirtAddr,
	phys_addr: PhysAddr,
}

impl JITMem {
	pub fn alloc() -> Self {
		let virt_address = crate::mm::virtualmem::allocate_aligned(4096, 4096).unwrap();
		let physical_address = crate::mm::physicalmem::allocate(4096).unwrap();

		let mut pte_flags = PageTableFlags::empty();
		pte_flags.normal().writable();
		crate::arch::mm::paging::map::<BasePageSize>(virt_address, physical_address, 1, pte_flags);

		Self {
			virt_addr: virt_address,
			phys_addr: physical_address,
		}
	}
}

impl Deref for JITMem {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		unsafe {
			let ptr = self.virt_addr.as_ptr();
			core::slice::from_raw_parts(ptr, 4096)
		}
	}
}

impl DerefMut for JITMem {
	fn deref_mut(&mut self) -> &mut Self::Target {
		unsafe {
			let ptr = self.virt_addr.as_mut_ptr();
			core::slice::from_raw_parts_mut(ptr, 4096)
		}
	}
}

impl Drop for JITMem {
	fn drop(&mut self) {
		crate::arch::mm::paging::unmap::<BasePageSize>(self.virt_addr, 1);
		crate::mm::physicalmem::deallocate(self.phys_addr, 4096);
		crate::mm::virtualmem::deallocate(self.virt_addr, 4096);
	}
}
