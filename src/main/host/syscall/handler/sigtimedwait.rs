use linux_api::errno::Errno;
use linux_api::signal::{Signal, siginfo_t, sigset_t};
use shadow_shim_helper_rs::simulation_time::SimulationTime;
use shadow_shim_helper_rs::syscall_types::ForeignPtr;

use crate::core::worker::Worker;
use crate::host::syscall::handler::{SyscallContext, SyscallHandler};
use crate::host::syscall::types::SyscallError;

/// How often a thread waiting without a timeout checks for its signals.
///
/// The signals waited for are normally blocked in the waiting thread, so
/// Shadow's signal delivery never wakes it; instead the thread polls, in
/// simulated time, for one of them to become pending.
const POLL_INTERVAL_MS: u64 = 10;

impl SyscallHandler {
    log_syscall!(
        rt_sigtimedwait,
        /* rv */ std::ffi::c_int,
        /* set */ *const std::ffi::c_void,
        /* info */ *const std::ffi::c_void,
        /* timeout */ *const std::ffi::c_void,
        /* sigsetsize */ libc::size_t,
    );
    /// rt_sigtimedwait(2), used by sigwait(3), sigwaitinfo(2) and
    /// sigtimedwait(2): takes a pending thread- or process-directed signal in
    /// `set` and returns its number.
    ///
    /// Without a timeout the thread polls every `POLL_INTERVAL_MS` of
    /// simulated time. With a timeout it checks once, sleeps for the whole
    /// timeout and checks again, so a signal arriving during the wait is
    /// noticed only when the timeout ends.
    pub fn rt_sigtimedwait(
        ctx: &mut SyscallContext,
        set_ptr: ForeignPtr<sigset_t>,
        info_ptr: ForeignPtr<siginfo_t>,
        timeout_ptr: ForeignPtr<linux_api::time::timespec>,
        sigsetsize: libc::size_t,
    ) -> Result<std::ffi::c_int, SyscallError> {
        if sigsetsize != size_of::<sigset_t>() {
            return Err(Errno::EINVAL.into());
        }
        let set = ctx.objs.process.memory_borrow().read(set_ptr)?;

        let taken: Option<(Signal, siginfo_t)> = {
            let shmem_lock = ctx.objs.host.shim_shmem_lock_borrow().unwrap();
            let thread_shmem = ctx.objs.thread.shmem();
            let mut thread_protected = thread_shmem.protected.borrow_mut(&shmem_lock.root);
            if let Some(signal) = (thread_protected.pending_signals & set).lowest() {
                let info = *thread_protected.pending_standard_siginfo(signal).unwrap();
                thread_protected.pending_signals.del(signal);
                Some((signal, info))
            } else {
                let process_shmem = ctx.objs.process.shmem();
                let mut process_protected =
                    process_shmem.protected.borrow_mut(&shmem_lock.root);
                if let Some(signal) = (process_protected.pending_signals & set).lowest() {
                    let info = *process_protected.pending_standard_siginfo(signal).unwrap();
                    process_protected.pending_signals.del(signal);
                    Some((signal, info))
                } else {
                    None
                }
            }
        };

        if let Some((signal, info)) = taken {
            if !info_ptr.is_null() {
                ctx.objs
                    .process
                    .memory_borrow_mut()
                    .write(info_ptr, &info)?;
            }
            return Ok(i32::from(signal));
        }

        let now = Worker::current_time().unwrap();
        if timeout_ptr.is_null() {
            return Err(SyscallError::new_blocked_until(
                now + SimulationTime::from_millis(POLL_INTERVAL_MS),
                false,
            ));
        }
        // Woke up at the end of the timeout without a signal.
        if ctx.objs.thread.syscall_condition().is_some() {
            return Err(Errno::EAGAIN.into());
        }
        let timeout = ctx.objs.process.memory_borrow().read(timeout_ptr)?;
        let timeout = SimulationTime::try_from(timeout).or(Err(Errno::EINVAL))?;
        if timeout == SimulationTime::ZERO {
            return Err(Errno::EAGAIN.into());
        }
        Err(SyscallError::new_blocked_until(now + timeout, false))
    }
}
