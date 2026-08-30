use std::fs::{File, OpenOptions};
use std::io::Write;

use anyhow::Context;

use crate::config::GenFlags;
use crate::crypto::{SecretKey, generate_secret_key_base64};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub fn generate(log: &slog::Logger, flags: &GenFlags) -> anyhow::Result<()> {
    let (secret_key, secret_key_base64, public_key) = generate_secret_key_base64();
    let (private_file, public_file) = open_key_files(flags)?;

    if let Some(mut file) = private_file {
        file.write_all(secret_key_base64.as_bytes())
            .context("Failed to write base64 to secret key file")?;
    } else {
        std::io::stdout()
            .lock()
            .write_all(format!("{secret_key_base64}\n").as_bytes())
            .context("Failed to write secret key to stdout")?;
    }

    slog::info!(log, "PublicKey is {}", secret_key.public_key());
    if let Some(mut file) = public_file {
        file.write_all(public_key.to_string().as_bytes())
            .context("Failed to write base64 to public key file")?;
    }

    let reloaded = SecretKey::try_from(secret_key_base64.as_str())
        .expect("Failed at reloading a key just generated");
    slog::debug!(
        log,
        "PublicKey after reloading from displayed secret is {}",
        reloaded.public_key()
    );
    Ok(())
}

fn open_key_files(flags: &GenFlags) -> anyhow::Result<(Option<File>, Option<File>)> {
    let private_file = match &flags.path {
        Some(path) => Some(open_private_key_file(path, flags)?),
        None => None,
    };
    let public_path = flags
        .pub_path
        .clone()
        .or_else(|| flags.path.clone().map(|path| path + ".pub"));
    let public_file = match public_path {
        Some(path) => Some(open_output_file(&path, flags.override_files, "public key")?),
        None => None,
    };

    Ok((private_file, public_file))
}

fn open_private_key_file(path: &str, flags: &GenFlags) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    configure_output_file(&mut options, flags.override_files);
    #[cfg(unix)]
    if !flags.insecure_priv {
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .context("Failed to open private key file for writing")?;

    #[cfg(unix)]
    if !flags.insecure_priv {
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)
            .context("Failed to set security permissions for private key file")?;
    }
    Ok(file)
}

fn open_output_file(path: &str, override_files: bool, description: &str) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    configure_output_file(&mut options, override_files);
    options
        .open(path)
        .with_context(|| format!("Failed to open {description} file for writing"))
}

fn configure_output_file(options: &mut OpenOptions, override_files: bool) {
    options.write(true);
    if override_files {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
}

#[cfg(test)]
mod tests {
    use super::open_key_files;
    use crate::config::GenFlags;
    use std::fs;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::SystemTime;

    #[test]
    fn overriding_a_private_key_file_truncates_and_secures_it() -> anyhow::Result<()> {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("p2p-tunnler-key-{unique}"));
        let path_text = path.to_string_lossy().to_string();
        let public_path = format!("{path_text}.pub");
        fs::write(&path, b"this previous key material is deliberately longer")?;

        let flags = GenFlags {
            path: Some(path_text),
            pub_path: None,
            insecure_priv: false,
            override_files: true,
        };
        let (private_file, public_file) = open_key_files(&flags)?;
        let mut private_file = private_file.expect("private key file should be open");
        private_file.write_all(b"replacement")?;
        drop(private_file);
        drop(public_file);

        assert_eq!(fs::read(&path)?, b"replacement");
        #[cfg(unix)]
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);

        fs::remove_file(&path)?;
        fs::remove_file(public_path)?;
        Ok(())
    }
}
