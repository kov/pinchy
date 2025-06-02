#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Pollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}
