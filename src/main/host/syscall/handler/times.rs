use shadow_shim_helper_rs::emulated_time::EmulatedTime;
use shadow_shim_helper_rs::syscall_types::ForeignPtr;

use crate::core::worker::Worker;
use crate::host::syscall::handler::{SyscallContext, SyscallHandler};
use crate::host::syscall::types::SyscallError;

/// USER_HZ: the unit of `clock_t` values returned by times(2) on Linux.
const USER_HZ: u64 = 100;

impl SyscallHandler {
    log_syscall!(
        times,
        /* rv */ std::ffi::c_long,
        /* buf */ *const std::ffi::c_void,
    );
    /// times(2): returns the simulated time since the start of the simulation
    /// in clock ticks, so the value advances with simulated time like the
    /// uptime that `sysinfo` reports. Shadow does not model CPU time, so the
    /// process CPU times in `struct tms` are reported as zero.
    pub fn times(
        ctx: &mut SyscallContext,
        buf_ptr: ForeignPtr<[std::ffi::c_long; 4]>,
    ) -> Result<std::ffi::c_long, SyscallError> {
        let since_start = Worker::current_time()
            .unwrap()
            .duration_since(&EmulatedTime::SIMULATION_START);
        let ticks = since_start.as_nanos() / (1_000_000_000 / u128::from(USER_HZ));
        let ticks = std::ffi::c_long::try_from(ticks).unwrap_or(std::ffi::c_long::MAX);

        if !buf_ptr.is_null() {
            // struct tms { clock_t tms_utime, tms_stime, tms_cutime, tms_cstime; }
            ctx.objs
                .process
                .memory_borrow_mut()
                .write(buf_ptr, &[0; 4])?;
        }

        Ok(ticks)
    }
}
