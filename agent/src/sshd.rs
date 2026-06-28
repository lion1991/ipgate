//! 探测系统 sshd 的认证态势（best-effort，读 `sshd -T` 的生效配置）。
//!
//! ADR 0007 把 SSH 当作 agent 的唯一入口，且 SSH 端口默认对全网开放（自锁不变量）。
//! 若服务器仍开着密码登录，这唯一的门就暴露在爆破面下——故把这点回报给客户端，便于告警。
//!
//! 局限：`sshd -T`（不带 `-C`）取的是**全局生效值**，`Match` 块里针对特定用户/来源放开的
//! 密码登录探测不到；任何环节拿不到（无 root / 无 sshd 二进制 / 调用失败）时各项为 `None`。

use anyhow::{bail, Context, Result};
use std::process::Command;

/// ipgate 托管的 sshd drop-in 路径。文件名以 `00-` 开头，确保在 `Include` 的字典序里**排最前**，
/// 压过 `50-cloud-init.conf` 之类默认打开密码登录的 drop-in（sshd 对每个关键字取**首个**取值）。
const DROPIN_PATH: &str = "/etc/ssh/sshd_config.d/00-ipgate-ssh.conf";

/// sshd 的认证相关生效配置（各项 `None` = 探测不到）。
#[derive(Debug, Clone, Default)]
pub struct SshAuth {
    /// `PasswordAuthentication` 是否为 yes（密码登录开启）。
    pub password: Option<bool>,
    /// `KbdInteractiveAuthentication`（旧名 `ChallengeResponseAuthentication`）是否为 yes：
    /// 开着 + PAM 可变相做密码登录，故视作密码登录面的一部分。
    pub kbd_interactive: Option<bool>,
    /// `PermitRootLogin` 原值（yes / no / prohibit-password / forced-commands-only）。
    pub permit_root: Option<String>,
}

/// 跑 `sshd -T` 并解析认证项；任何环节失败都退化为「探测不到」（不 panic、不报错）。
pub fn probe() -> SshAuth {
    match run_sshd_t() {
        Some(text) => parse(&text),
        None => SshAuth::default(),
    }
}

/// 依次尝试 PATH 与常见绝对路径（systemd 服务里 root 的 PATH 常不含 /usr/sbin）。
fn run_sshd_t() -> Option<String> {
    for bin in ["sshd", "/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"] {
        if let Ok(out) = Command::new(bin).arg("-T").output() {
            if out.status.success() {
                if let Ok(s) = String::from_utf8(out.stdout) {
                    return Some(s);
                }
            }
        }
    }
    None
}

/// 解析 `sshd -T` 输出（每行 `key value`，key 恒为小写）。
fn parse(text: &str) -> SshAuth {
    let mut a = SshAuth::default();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(key), Some(val)) = (it.next(), it.next()) else {
            continue;
        };
        let yes = val.eq_ignore_ascii_case("yes");
        match key {
            "passwordauthentication" => a.password = Some(yes),
            // 新版 sshd 打印 kbdinteractive…，老版打印 challengeresponse…；两者都认，kbd 优先。
            "kbdinteractiveauthentication" => a.kbd_interactive = Some(yes),
            "challengeresponseauthentication" if a.kbd_interactive.is_none() => {
                a.kbd_interactive = Some(yes)
            }
            "permitrootlogin" => a.permit_root = Some(val.to_string()),
            _ => {}
        }
    }
    a
}

/// 渲染 ipgate sshd drop-in 内容（纯函数，可测）。
/// 关闭时连 `KbdInteractive` 一并设为 no——它 + PAM 可变相做密码登录，要关就关干净。
fn dropin_content(password_enabled: bool) -> String {
    let head = "# Managed by ipgate-agent —— 勿手改，客户端会覆盖本文件。\n";
    if password_enabled {
        format!("{head}PasswordAuthentication yes\n")
    } else {
        format!("{head}PasswordAuthentication no\nKbdInteractiveAuthentication no\n")
    }
}

/// 开/关 SSH 密码登录：写 drop-in → `sshd -t` 校验 → reload → 复查生效。任一步失败均回滚。
///
/// reload 用 SIGHUP，不断现有连接（客户端的隧道是已建立连接，安然无恙）；只对新连接生效。
pub fn set_password_auth(enabled: bool) -> Result<()> {
    // 备份旧 drop-in 以便回滚（None = 原本不存在）。
    let prev = std::fs::read(DROPIN_PATH).ok();

    write_dropin(&dropin_content(enabled)).with_context(|| format!("写入 {DROPIN_PATH} 失败"))?;

    // sshd -t 校验：配置非法绝不 reload（带病 reload 可能让 sshd 起不来＝自锁）。
    if let Err(e) = validate_sshd_config() {
        restore_dropin(prev.as_deref());
        return Err(e.context("sshd 配置校验失败，已回滚 drop-in"));
    }
    if let Err(e) = reload_sshd() {
        restore_dropin(prev.as_deref());
        return Err(e.context("reload sshd 失败，已回滚 drop-in"));
    }
    // 复查：drop-in 理应排最前生效；若没生效，多半是 sshd_config 在更靠前处显式写死了该项。
    let got = probe().password;
    if got != Some(enabled) {
        restore_dropin(prev.as_deref());
        let _ = reload_sshd();
        bail!(
            "drop-in 已写入但未生效（当前 PasswordAuthentication={got:?}）——\
             sshd_config 可能在更靠前处显式设置了该项，需手动处理。已回滚。"
        );
    }
    Ok(())
}

/// 重置 root 密码：`chpasswd` 走 stdin（不进 argv/ps/日志）。明文由调用方经 Noise 隧道送达。
pub fn reset_root_password(password: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;
    if password.is_empty() {
        bail!("密码为空");
    }
    let mut child = Command::new("chpasswd")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("启动 chpasswd 失败")?;
    {
        let mut stdin = child.stdin.take().context("chpasswd stdin 不可用")?;
        // chpasswd 读 `user:password` 行；密文由其按系统默认算法哈希。
        writeln!(stdin, "root:{password}").context("写 chpasswd stdin 失败")?;
    } // stdin 在此 drop → EOF
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("chpasswd 失败：{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn write_dropin(content: &str) -> Result<()> {
    let path = std::path::Path::new(DROPIN_PATH);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("conf.tmp");
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn restore_dropin(prev: Option<&[u8]>) {
    match prev {
        Some(bytes) => {
            let _ = std::fs::write(DROPIN_PATH, bytes);
        }
        None => {
            let _ = std::fs::remove_file(DROPIN_PATH);
        }
    }
}

/// `sshd -t`：校验当前生效配置是否能起。失败返回其 stderr。
fn validate_sshd_config() -> Result<()> {
    for bin in ["sshd", "/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"] {
        if let Ok(out) = Command::new(bin).arg("-t").output() {
            if out.status.success() {
                return Ok(());
            }
            bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
        }
    }
    bail!("找不到 sshd 可执行文件")
}

/// reload（SIGHUP，不断连接）优先；服务名 Debian=ssh / RHEL=sshd，都试；最后退化为 restart。
fn reload_sshd() -> Result<()> {
    for (action, svc) in [
        ("reload", "ssh"),
        ("reload", "sshd"),
        ("restart", "ssh"),
        ("restart", "sshd"),
    ] {
        if let Ok(out) = Command::new("systemctl").arg(action).arg(svc).output() {
            if out.status.success() {
                return Ok(());
            }
        }
    }
    bail!("systemctl reload/restart ssh|sshd 均失败")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hardened_config() {
        let t = "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin prohibit-password\n";
        let a = parse(t);
        assert_eq!(a.password, Some(false));
        assert_eq!(a.kbd_interactive, Some(false));
        assert_eq!(a.permit_root.as_deref(), Some("prohibit-password"));
    }

    #[test]
    fn parses_open_config_and_legacy_key() {
        let t = "passwordauthentication yes\nchallengeresponseauthentication yes\npermitrootlogin yes\n";
        let a = parse(t);
        assert_eq!(a.password, Some(true));
        assert_eq!(a.kbd_interactive, Some(true));
        assert_eq!(a.permit_root.as_deref(), Some("yes"));
    }

    #[test]
    fn newer_kbd_key_wins_over_legacy() {
        // 两个键都在时（理论上不会），以 kbdinteractive 为准。
        let t = "kbdinteractiveauthentication no\nchallengeresponseauthentication yes\n";
        assert_eq!(parse(t).kbd_interactive, Some(false));
    }

    #[test]
    fn dropin_renders_both_directions() {
        let on = dropin_content(true);
        assert!(on.contains("PasswordAuthentication yes"));
        assert!(!on.contains(" no"));
        let off = dropin_content(false);
        assert!(off.contains("PasswordAuthentication no"));
        assert!(off.contains("KbdInteractiveAuthentication no")); // 关就关干净
        assert!(off.starts_with("# Managed by ipgate-agent"));
    }

    #[test]
    fn missing_keys_stay_none() {
        let a = parse("port 2222\nciphers aes256-gcm@openssh.com\n");
        assert!(a.password.is_none());
        assert!(a.kbd_interactive.is_none());
        assert!(a.permit_root.is_none());
    }
}
