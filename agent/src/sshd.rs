//! 探测系统 sshd 的认证态势（best-effort，读 `sshd -T` 的生效配置）。
//!
//! ADR 0007 把 SSH 当作 agent 的唯一入口，且 SSH 端口默认对全网开放（自锁不变量）。
//! 若服务器仍开着密码登录，这唯一的门就暴露在爆破面下——故把这点回报给客户端，便于告警。
//!
//! 局限：`sshd -T`（不带 `-C`）取的是**全局生效值**，`Match` 块里针对特定用户/来源放开的
//! 密码登录探测不到；任何环节拿不到（无 root / 无 sshd 二进制 / 调用失败）时各项为 `None`。

use anyhow::{bail, Context, Result};
use std::process::Command;

/// 主 sshd 配置。受管块插到它**最顶部**：sshd 对每个关键字取**首个**取值，故顶部块必胜——
/// 覆盖任何更靠后的设置（包括 `Include` 进来的 drop-in、以及主配置后文的显式 `PasswordAuthentication`）。
/// drop-in 方案不可靠：若主配置在 `Include` 之前显式设了该项，drop-in 会被压住（实测踩到）。
const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
/// 0.2.3 曾用的 drop-in 路径——现已弃用，每次写主配置时顺手删掉，避免两处来源混淆。
const DROPIN_PATH: &str = "/etc/ssh/sshd_config.d/00-ipgate-ssh.conf";
/// 受管块的起止标记（注释行）。幂等改写靠它定位旧块。
const MARK_BEGIN: &str = "# >>> ipgate-agent managed (ssh password auth) >>>";
const MARK_END: &str = "# <<< ipgate-agent managed <<<";

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

/// 受管块内容（纯函数，可测）。关闭时连 `KbdInteractive` 一并设为 no——它 + PAM 可变相
/// 做密码登录，要关就关干净。带醒目注释，便于用户认出/手动删除。
fn managed_block(enabled: bool) -> String {
    let body = if enabled {
        "PasswordAuthentication yes\n"
    } else {
        "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
    };
    format!("{MARK_BEGIN}\n# 由 ipgate 客户端管理，勿手改；删除本块即恢复你原本的设置。\n{body}{MARK_END}\n")
}

/// 删除文本里 `MARK_BEGIN..=MARK_END` 之间（含标记行）的内容，返回其余部分（行尾规整为 \n）。
fn strip_managed_block(text: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in text.lines() {
        let t = line.trim();
        if t == MARK_BEGIN {
            skipping = true;
            continue;
        }
        if t == MARK_END {
            skipping = false;
            continue;
        }
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// 开/关 SSH 密码登录：在主 sshd_config **顶部**插受管块 → `sshd -t` 校验 → reload → 复查生效。
/// 任一步失败把主配置回滚到调用前并 reload，绝不残留半成品/坏配置。
///
/// reload 用 SIGHUP，不断现有连接（客户端的隧道是已建立连接，安然无恙）；只对新连接生效。
pub fn set_password_auth(enabled: bool) -> Result<()> {
    let prev_main =
        std::fs::read_to_string(SSHD_CONFIG).with_context(|| format!("读取 {SSHD_CONFIG} 失败"))?;

    // 幂等：先删旧受管块，再把新块插到最顶部（首个取值必胜）。
    let new_main = format!("{}{}", managed_block(enabled), strip_managed_block(&prev_main));
    write_atomic(SSHD_CONFIG, &new_main).with_context(|| format!("写入 {SSHD_CONFIG} 失败"))?;
    // 顺手清掉 0.2.3 的旧 drop-in，避免两处来源混淆（主配置受管块已是权威）。
    let _ = std::fs::remove_file(DROPIN_PATH);

    let outcome = (|| -> Result<()> {
        // 配置非法绝不 reload（带病 reload 可能让 sshd 起不来＝自锁）。
        validate_sshd_config().context("sshd 配置校验失败")?;
        reload_sshd().context("reload sshd 失败")?;
        let got = probe().password;
        if got != Some(enabled) {
            bail!("reload 后 PasswordAuthentication 仍为 {got:?}（期望 {enabled}）");
        }
        Ok(())
    })();

    if outcome.is_err() {
        let _ = write_atomic(SSHD_CONFIG, &prev_main); // 回滚到调用前
        let _ = reload_sshd();
    }
    outcome
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

/// 原子写（temp + rename），保留原文件权限。
fn write_atomic(path: &str, content: &str) -> Result<()> {
    let p = std::path::Path::new(path);
    let tmp = p.with_extension("ipgate.tmp");
    std::fs::write(&tmp, content)?;
    // 尽力沿用原文件权限（sshd_config 通常 0644，root 拥有）。
    if let Ok(meta) = std::fs::metadata(p) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    std::fs::rename(&tmp, p)?;
    Ok(())
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
    fn managed_block_both_directions() {
        let on = managed_block(true);
        assert!(on.contains("PasswordAuthentication yes"));
        let off = managed_block(false);
        assert!(off.contains("PasswordAuthentication no"));
        assert!(off.contains("KbdInteractiveAuthentication no")); // 关就关干净
        assert!(off.starts_with(MARK_BEGIN));
        assert!(off.trim_end().ends_with(MARK_END));
    }

    #[test]
    fn strip_removes_block_and_is_idempotent() {
        let orig = "Port 22\nPasswordAuthentication yes\n";
        let with = format!("{}{}", managed_block(false), orig);
        assert!(with.contains("PasswordAuthentication no"));
        // 删受管块 → 完全还原原文。
        assert_eq!(strip_managed_block(&with), orig);
        // 再插一次（不同方向）再删，仍还原（幂等，不累积）。
        let with2 = format!("{}{}", managed_block(true), strip_managed_block(&with));
        assert_eq!(strip_managed_block(&with2), orig);
    }

    #[test]
    fn missing_keys_stay_none() {
        let a = parse("port 2222\nciphers aes256-gcm@openssh.com\n");
        assert!(a.password.is_none());
        assert!(a.kbd_interactive.is_none());
        assert!(a.permit_root.is_none());
    }
}
