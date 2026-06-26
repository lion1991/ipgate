//! 跨进程独占文件锁（`flock(2)` `LOCK_EX`）。
//!
//! 与 dnat 工具的 `lock.go` **同语义、可互斥**：双方都对同一 `conf.lock`
//! 取 advisory flock，因此 ipgate 改 dnat conf 时不会与 dnat daemon/TUI 撞车
//! （ADR 0006）。`Drop` 时解锁并关闭。

use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// 持有期间独占锁定 `path`；`Drop` 释放。
pub struct FileLock {
    file: File,
}

impl FileLock {
    /// 阻塞获取独占锁（锁文件不存在则以 0600 创建，与 dnat 一致）。
    pub fn acquire(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("建锁目录 {} 失败", dir.display()))?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // 仅取 fd 做 flock，绝不清空锁文件内容
            .mode(0o600)
            .open(path)
            .with_context(|| format!("打开锁文件 {} 失败", path.display()))?;
        // SAFETY: fd 来自上面打开的 File，存活于 self.file，flock 不转移所有权。
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("flock {} 失败", path.display()));
        }
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // 关闭 fd 本身就会释放 flock；显式 LOCK_UN 仅为表意。
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}
