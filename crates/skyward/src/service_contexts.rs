use anyhow::{bail, ensure, Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const PLATFORM_SERVICE_CONTEXTS_SOURCE: &str =
    "/mnt/system/system/etc/selinux/plat_service_contexts";
pub(crate) const PLATFORM_SERVICE_CONTEXTS_TARGET: &str =
    "/system/etc/selinux/plat_service_contexts";

pub(crate) fn uses_aidl_service_contexts(names: &[String]) -> bool {
    names
        .iter()
        .any(|name| name.contains('/') && !name.contains('@'))
}

pub(crate) fn install_platform_service_contexts() -> Result<bool> {
    let source = Path::new(PLATFORM_SERVICE_CONTEXTS_SOURCE);
    let target = Path::new(PLATFORM_SERVICE_CONTEXTS_TARGET);
    let parent = target
        .parent()
        .expect("service contexts have a parent directory");
    fs::create_dir_all(parent).with_context(|| format!("make {}", parent.display()))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("open {} to every user", parent.display()))?;

    if source.is_file() {
        copy_service_contexts(source, target)
    } else if target.is_file() {
        let metadata = fs::symlink_metadata(target)
            .with_context(|| format!("inspect {}", target.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "{} is not a regular file",
            target.display()
        );
        if metadata.permissions().mode() & 0o777 == 0o644 {
            Ok(false)
        } else {
            fs::set_permissions(target, fs::Permissions::from_mode(0o644))
                .with_context(|| format!("set mode on {}", target.display()))?;
            Ok(true)
        }
    } else {
        bail!(
            "neither {} nor {} is a regular file",
            source.display(),
            target.display()
        )
    }
}

fn copy_service_contexts(source: &Path, target: &Path) -> Result<bool> {
    let contents = fs::read(source).with_context(|| format!("read {}", source.display()))?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).with_context(|| format!("make {}", parent.display()))?;
    }
    let existing = match fs::symlink_metadata(target) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file(),
                "{} is not a regular file",
                target.display()
            );
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).with_context(|| format!("inspect {}", target.display())),
    };
    let same_contents = if existing.is_some() {
        fs::read(target).with_context(|| format!("read {}", target.display()))? == contents
    } else {
        false
    };
    if same_contents
        && existing
            .as_ref()
            .is_some_and(|metadata| metadata.permissions().mode() & 0o777 == 0o644)
    {
        return Ok(false);
    }
    if same_contents {
        fs::set_permissions(target, fs::Permissions::from_mode(0o644))
            .with_context(|| format!("set mode on {}", target.display()))?;
        return Ok(true);
    }
    fs::write(target, contents).with_context(|| format!("write {}", target.display()))?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("set mode on {}", target.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{copy_service_contexts, uses_aidl_service_contexts};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn copies_platform_service_contexts_for_the_recovery_service_manager() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("plat_service_contexts");
        let target_dir = temp.path().join("recovery_selinux");
        fs::create_dir_all(&target_dir).unwrap();
        let target = target_dir.join("plat_service_contexts");
        let contents = b"android.hardware.security.keymint.IKeyMintDevice/default u:object_r:hal_keymint_service:s0\n";
        fs::write(&source, contents).unwrap();

        assert!(copy_service_contexts(&source, &target).unwrap());
        assert_eq!(fs::read(&target).unwrap(), contents);
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(!copy_service_contexts(&source, &target).unwrap());
    }

    #[test]
    fn recognizes_aidl_names_but_not_hidl_names() {
        let aidl = vec!["android.hardware.security.keymint.IKeyMintDevice/default".to_owned()];
        let hidl = vec!["android.hardware.keymaster@4.1::IKeymasterDevice/default".to_owned()];

        assert!(uses_aidl_service_contexts(&aidl));
        assert!(!uses_aidl_service_contexts(&hidl));
    }
}
