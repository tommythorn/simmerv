use num_derive::FromPrimitive;
use std::convert::TryFrom;

#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq, Eq)]
pub enum Trap {
    InstructionAddressMisaligned = 0,
    InstructionAccessFault,
    IllegalInstruction,
    Breakpoint,
    LoadAddressMisaligned,
    LoadAccessFault,
    StoreAddressMisaligned,
    StoreAccessFault,
    EnvironmentCallFromUMode,
    EnvironmentCallFromSMode,
    // Reserved
    EnvironmentCallFromMMode = 11,
    InstructionPageFault,
    LoadPageFault,
    // Reserved
    StorePageFault = 15,

    UserSoftwareInterrupt = 100,
    SupervisorSoftwareInterrupt = 101,
    MachineSoftwareInterrupt = 103,

    UserTimerInterrupt = 104,
    SupervisorTimerInterrupt = 105,
    MachineTimerInterrupt = 107,

    UserExternalInterrupt = 108,
    SupervisorExternalInterrupt = 109,
    MachineExternalInterrupt = 111,

    // Sscofpmf local counter-overflow interrupt (interrupt 13).  The encoding
    // here is 100 + interrupt number; see get_trap_cause.
    CounterOverflowInterrupt = 113,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivMode {
    U,
    S,
    M,
}

impl TryFrom<u64> for PrivMode {
    type Error = ();
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        match x {
            0 => Ok(Self::U),
            1 => Ok(Self::S),
            3 => Ok(Self::M),
            _ => Err(()),
        }
    }
}

impl From<PrivMode> for u64 {
    fn from(x: PrivMode) -> Self {
        match x {
            PrivMode::U => 0,
            PrivMode::S => 1,
            PrivMode::M => 3,
        }
    }
}

/// Returns `PrivMode` from encoded privilege mode bits
/// # Panics
/// On unknown modes crash
#[must_use]
pub fn priv_mode_from(encoding: u64) -> PrivMode {
    assert_ne!(encoding, 2);
    let Ok(m) = PrivMode::try_from(encoding) else {
        unreachable!();
    };
    m
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MemoryAccessType {
    Execute,
    Read,
    Write,
}
