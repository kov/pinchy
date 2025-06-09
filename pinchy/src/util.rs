// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Gustavo Noronha Silva <gustavo@noronha.dev.br>

pub fn poll_bits_to_strs(event: &i16) -> Vec<&'static str> {
    let mut strs = vec![];

    if event & libc::POLLIN != 0 {
        strs.push("POLLIN");
    }

    if event & libc::POLLPRI != 0 {
        strs.push("POLLPRI");
    }

    if event & libc::POLLOUT != 0 {
        strs.push("POLLOUT");
    }

    if event & libc::POLLRDHUP != 0 {
        strs.push("POLLRDHUP");
    }

    if event & libc::POLLERR != 0 {
        strs.push("POLLERR");
    }

    if event & libc::POLLHUP != 0 {
        strs.push("POLLHUP");
    }

    if event & libc::POLLNVAL != 0 {
        strs.push("POLLNVAL");
    }

    if event & libc::POLLRDNORM != 0 {
        strs.push("POLLRDNORM");
    }

    if event & libc::POLLRDBAND != 0 {
        strs.push("POLLRDBAND");
    }

    if event & libc::POLLWRNORM != 0 {
        strs.push("POLLWRNORM");
    }

    if event & libc::POLLWRBAND != 0 {
        strs.push("POLLWRBAND");
    }

    strs
}
