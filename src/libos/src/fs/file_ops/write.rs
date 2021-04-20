use super::*;

pub fn do_write(fd: FileDesc, buf: &[u8]) -> Result<usize> {
    let path = get_abs_path_by_fd(fd);
    if path.is_ok() {
        warn!("write: fd: {}, path = {:?}", fd, path);
    } else {
        warn!(
            "write: fd: {} (channel: {})",
            fd,
            get_channel_id_from_fd(fd).0
        );
    }
    let file_ref = current!().file(fd)?;
    let ret = file_ref.write(buf);
    let string = std::str::from_utf8(&buf);
    if string.is_ok() {
        warn!("write buf: {:?}", string.unwrap());
    }
    return ret;
}

pub fn do_writev(fd: FileDesc, bufs: &[&[u8]]) -> Result<usize> {
    debug!("writev: fd: {}", fd);
    let file_ref = current!().file(fd)?;
    file_ref.writev(bufs)
}

pub fn do_pwrite(fd: FileDesc, buf: &[u8], offset: off_t) -> Result<usize> {
    debug!("pwrite: fd: {}, offset: {}", fd, offset);
    if offset < 0 {
        return_errno!(EINVAL, "the offset is negative");
    }
    let file_ref = current!().file(fd)?;
    file_ref.write_at(offset as usize, buf)
}
