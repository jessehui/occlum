use super::*;

pub fn do_read(fd: FileDesc, buf: &mut [u8]) -> Result<usize> {
    let path = get_abs_path_by_fd(fd);
    if path.is_ok() {
        warn!("read: fd: {}, path = {:?}", fd, path);
    } else {
        warn!(
            "read: fd: {} (channel: {})",
            fd,
            get_channel_id_from_fd(fd).0
        );
    }
    let file_ref = current!().file(fd)?;
    let ret = file_ref.read(buf);
    let string = std::str::from_utf8(&buf);
    if string.is_ok() {
        warn!("read buf: {:?}", string.unwrap());
    }
    return ret;
}

pub fn do_readv(fd: FileDesc, bufs: &mut [&mut [u8]]) -> Result<usize> {
    debug!("readv: fd: {}", fd);
    let file_ref = current!().file(fd)?;
    file_ref.readv(bufs)
}

pub fn do_pread(fd: FileDesc, buf: &mut [u8], offset: off_t) -> Result<usize> {
    debug!("pread: fd: {}, offset: {}", fd, offset);
    if offset < 0 {
        return_errno!(EINVAL, "the offset is negative");
    }
    let file_ref = current!().file(fd)?;
    file_ref.read_at(offset as usize, buf)
}
