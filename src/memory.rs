use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    io,
    ptr::NonNull,
};
use zeroize::Zeroize;

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct MemoryInfo {
    pub physical: u64,
    pub page_size: u64,
    pub free_bytes: u64,
    pub inactive_bytes: u64,
    pub wired_bytes: u64,
    pub compressed_bytes: u64,
    pub pressure: u32,
    pub pressure_known: u32,
}
unsafe extern "C" {
    fn rammesh_memory_info(info: *mut MemoryInfo) -> libc::c_int;
    fn rammesh_region_info(
        address: u64,
        size: *mut u64,
        resident: *mut u64,
        swapped: *mut u64,
        external: *mut u32,
        wired: *mut u32,
    ) -> libc::c_int;
}
impl MemoryInfo {
    pub fn get() -> io::Result<Self> {
        let mut info = Self::default();
        if unsafe { rammesh_memory_info(&mut info) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }
    pub fn allocation_allowed(&self, reserve: u64) -> bool {
        self.pressure_known != 0
            && self.pressure == 1
            && self.free_bytes.saturating_add(self.inactive_bytes) >= reserve
    }
    pub fn json(&self) -> Value {
        json!({"physical_bytes":self.physical,"page_size":self.page_size,"free_bytes":self.free_bytes,
            "inactive_bytes":self.inactive_bytes,"wired_bytes_system":self.wired_bytes,
            "compressed_bytes_system":self.compressed_bytes,"pressure_level":self.pressure,
            "pressure_known":self.pressure_known != 0,
            "headroom_note":"free + inactive is an estimate, not guaranteed available RAM"})
    }
}

/// The only bulk data storage: an anonymous mapping, wired before it is advertised.
pub struct WiredMemory {
    ptr: NonNull<u8>,
    pub len: usize,
    pub page: usize,
}
// Safety: exclusive mutation requires &mut self, and Pool is protected by a mutex.
unsafe impl Send for WiredMemory {}
impl WiredMemory {
    pub fn new(len: usize) -> io::Result<Self> {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        if len == 0 || !len.is_multiple_of(page) {
            return Err(io::Error::other("pool must be a positive page multiple"));
        }
        // Darwin's MAP_ANON fd encodes a VM tag. 240 makes the mapping identifiable in vmmap.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                (240u32 << 24) as i32,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::mlock(ptr, len) } != 0 {
            let e = io::Error::last_os_error();
            unsafe {
                libc::munmap(ptr, len);
            }
            return Err(io::Error::other(format!(
                "mlock failed; refusing pageable donation: {e}"
            )));
        }
        // Fault/touch every byte before serving. No file, shared-memory file or ramdisk is opened.
        unsafe {
            std::ptr::write_bytes(ptr, 0, len);
        }
        Ok(Self {
            ptr: NonNull::new(ptr.cast()).unwrap(),
            len,
            page,
        })
    }
    fn bytes(&self, start: usize, len: usize) -> &[u8] {
        assert!(start <= self.len && len <= self.len - start);
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().add(start), len) }
    }
    fn bytes_mut(&mut self, start: usize, len: usize) -> &mut [u8] {
        assert!(start <= self.len && len <= self.len - start);
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr().add(start), len) }
    }
    fn erase(&mut self, start: usize, len: usize) {
        assert!(start <= self.len && len <= self.len - start);
        // Volatile zeroization cannot be optimized out; erase while still wired.
        self.bytes_mut(start, len).zeroize();
    }
    pub fn evidence(&self) -> io::Result<Value> {
        let pages = self.len / self.page;
        let mut states = vec![0i8; pages];
        if unsafe { libc::mincore(self.ptr.as_ptr().cast(), self.len, states.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let resident = states.iter().filter(|s| **s & 1 != 0).count();
        let paged_out = states.iter().filter(|s| **s & 0x20 != 0).count();
        let (mut region_size, mut region_resident, mut swapped, mut external, mut wired) =
            (0, 0, 0, 0, 0);
        let region_ok = unsafe {
            rammesh_region_info(
                self.ptr.as_ptr() as u64,
                &mut region_size,
                &mut region_resident,
                &mut swapped,
                &mut external,
                &mut wired,
            )
        } == 0;
        Ok(
            json!({"mapping":"MAP_PRIVATE | MAP_ANON; VM tag 240","mlock_succeeded":true,
            "address":format!("0x{:x}", self.ptr.as_ptr() as usize),"capacity_bytes":self.len,
            "total_pages":pages,"resident_pages":resident,"paged_out_pages":paged_out,
            "all_resident":resident == pages,"vm_region_query_ok":region_ok,
            "vm_region_bytes":region_size,"vm_region_resident_pages":region_resident,
            "vm_region_swapped_pages":swapped,"vm_region_external_pager":external,
            "vm_region_user_wired_count":wired}),
        )
    }
}
impl Drop for WiredMemory {
    fn drop(&mut self) {
        self.erase(0, self.len);
        unsafe {
            libc::munlock(self.ptr.as_ptr().cast(), self.len);
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

struct Allocation {
    owner: u64,
    start: usize,
    requested: usize,
    billed: usize,
}
pub struct Pool {
    pub memory: WiredMemory,
    free: BTreeMap<usize, usize>,
    allocations: HashMap<u64, Allocation>,
    next_id: u64,
    pub used: usize,
    pub peak: usize,
    pub session_limit: usize,
    pub max_allocations: usize,
}
impl Pool {
    pub fn new(bytes: usize, session_limit: usize, max_allocations: usize) -> io::Result<Self> {
        Ok(Self {
            memory: WiredMemory::new(bytes)?,
            free: BTreeMap::from([(0, bytes)]),
            allocations: HashMap::new(),
            next_id: 1,
            used: 0,
            peak: 0,
            session_limit,
            max_allocations,
        })
    }
    pub fn alloc(&mut self, owner: u64, bytes: u64) -> Result<(u64, usize), &'static str> {
        let n = usize::try_from(bytes).map_err(|_| "invalid size")?;
        if n == 0 || n > self.memory.len {
            return Err("size exceeds pool or is zero");
        }
        let billed = n.checked_add(self.memory.page - 1).ok_or("overflow")? / self.memory.page
            * self.memory.page;
        let owned: usize = self
            .allocations
            .values()
            .filter(|a| a.owner == owner)
            .map(|a| a.billed)
            .sum();
        if billed > self.session_limit.saturating_sub(owned) {
            return Err("session quota exceeded");
        }
        if self.allocations.len() >= self.max_allocations {
            return Err("allocation count limit");
        }
        let (&start, &available) = self
            .free
            .iter()
            .find(|(_, n)| **n >= billed)
            .ok_or("pool full or fragmented")?;
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or("id exhausted")?;
        self.free.remove(&start);
        if available > billed {
            self.free.insert(start + billed, available - billed);
        }
        self.allocations.insert(
            id,
            Allocation {
                owner,
                start,
                requested: n,
                billed,
            },
        );
        self.used += billed;
        self.peak = self.peak.max(self.used);
        Ok((id, billed))
    }
    fn range(&self, owner: u64, id: u64, offset: u64, n: usize) -> Result<usize, &'static str> {
        let a = self
            .allocations
            .get(&id)
            .filter(|a| a.owner == owner)
            .ok_or("unknown allocation")?;
        let offset = usize::try_from(offset).map_err(|_| "offset overflow")?;
        if offset > a.requested || n > a.requested - offset {
            return Err("out of bounds");
        }
        Ok(a.start + offset)
    }
    pub fn read(&self, owner: u64, id: u64, offset: u64, n: usize) -> Result<&[u8], &'static str> {
        let start = self.range(owner, id, offset, n)?;
        Ok(self.memory.bytes(start, n))
    }
    pub fn write(
        &mut self,
        owner: u64,
        id: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<(), &'static str> {
        let start = self.range(owner, id, offset, data.len())?;
        self.memory
            .bytes_mut(start, data.len())
            .copy_from_slice(data);
        Ok(())
    }
    pub fn free(&mut self, owner: u64, id: u64) -> Result<(), &'static str> {
        self.allocations
            .get(&id)
            .filter(|a| a.owner == owner)
            .ok_or("unknown allocation")?;
        let a = self.allocations.remove(&id).unwrap();
        self.memory.erase(a.start, a.billed);
        self.used -= a.billed;
        let (mut start, mut len) = (a.start, a.billed);
        if let Some((&p, &n)) = self.free.range(..start).next_back()
            && p + n == start
        {
            self.free.remove(&p);
            start = p;
            len += n;
        }
        if let Some((&p, &n)) = self.free.range(start..).next()
            && start + len == p
        {
            self.free.remove(&p);
            len += n;
        }
        self.free.insert(start, len);
        Ok(())
    }
    pub fn release_owner(&mut self, owner: u64) {
        let ids: Vec<_> = self
            .allocations
            .iter()
            .filter(|(_, a)| a.owner == owner)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.free(owner, id).unwrap();
        }
    }
    pub fn stats(&self) -> Value {
        json!({"capacity_bytes":self.memory.len,"used_bytes":self.used,"peak_used_bytes":self.peak,
            "free_bytes":self.memory.len-self.used,"allocations":self.allocations.len(),
            "max_allocations":self.max_allocations,"session_limit_bytes":self.session_limit,
            "free_extents":self.free.len()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ownership_bounds_quota_zeroing_and_coalescing() {
        let mut p = Pool::new(4 * 4096, 3 * 4096, 8).unwrap();
        let (a, billed) = p.alloc(1, 17).unwrap();
        assert_eq!(billed, 4096);
        p.write(1, a, 0, &[7; 17]).unwrap();
        assert!(p.read(2, a, 0, 1).is_err());
        assert!(p.free(2, a).is_err());
        assert!(p.read(1, a, u64::MAX, 1).is_err());
        assert!(p.write(1, a, 16, &[1, 2]).is_err());
        assert!(p.alloc(1, u64::MAX).is_err());
        assert!(p.alloc(1, 0).is_err());
        let (b, _) = p.alloc(1, 8192).unwrap();
        assert!(p.alloc(1, 1).is_err());
        p.free(1, a).unwrap();
        let (c, _) = p.alloc(2, 17).unwrap();
        assert_eq!(p.read(2, c, 0, 17).unwrap(), &[0; 17]);
        p.free(1, b).unwrap();
        p.release_owner(2);
        assert_eq!(p.free, BTreeMap::from([(0, 16384)]));
        assert_eq!(p.used, 0);
        assert!(
            p.memory.evidence().unwrap()["all_resident"]
                .as_bool()
                .unwrap()
        );
    }
}
