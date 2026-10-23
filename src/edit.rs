use crate::prelude::*;

use std::io::{Read as _, Write as _};

use is_terminal::IsTerminal as _;

pub fn edit(contents: &str, help: &str) -> Result<String> {
    edit_with_options(contents, help, false)
}

pub fn edit_with_options(
    contents: &str,
    help: &str,
    allow_empty: bool,
) -> Result<String> {
    if let Some(input) = read_stdin(allow_empty)? {
        return Ok(input);
    }

    let mut var = "VISUAL";
    let editor = std::env::var_os(var).unwrap_or_else(|| {
        var = "EDITOR";
        std::env::var_os(var).unwrap_or_else(|| "/usr/bin/vim".into())
    });

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rbw");
    let mut fh = std::fs::File::create(&file).unwrap();
    fh.write_all(contents.as_bytes()).unwrap();
    fh.write_all(help.as_bytes()).unwrap();
    drop(fh);

    let (cmd, args) = if contains_shell_metacharacters(&editor) {
        let mut cmdline = std::ffi::OsString::new();
        cmdline.extend([
            editor.as_ref(),
            std::ffi::OsStr::new(" "),
            file.as_os_str(),
        ]);

        let editor_args = vec![std::ffi::OsString::from("-c"), cmdline];
        (std::path::Path::new("/bin/sh"), editor_args)
    } else {
        let editor = std::path::Path::new(&editor);
        let mut editor_args = vec![];

        #[allow(clippy::single_match_else)] // more to come
        match editor.file_name() {
            Some(editor) => match editor.to_str() {
                Some("vim" | "nvim") => {
                    // disable swap files and viminfo for password entry
                    editor_args.push(std::ffi::OsString::from("-ni"));
                    editor_args.push(std::ffi::OsString::from("NONE"));
                }
                _ => {
                    // other editor support welcomed
                }
            },
            None => {
                return Err(Error::InvalidEditor {
                    var: var.to_string(),
                    editor: editor.as_os_str().to_os_string(),
                })
            }
        }
        editor_args.push(file.clone().into_os_string());
        (editor, editor_args)
    };

    let res = std::process::Command::new(cmd).args(&args).status();
    match res {
        Ok(res) => {
            if !res.success() {
                return Err(Error::FailedToRunEditor {
                    editor: cmd.to_owned(),
                    args,
                    res,
                });
            }
        }
        Err(err) => {
            return Err(Error::FailedToFindEditor {
                editor: cmd.to_owned(),
                err,
            })
        }
    }

    let mut fh = std::fs::File::open(&file).unwrap();
    let mut contents = String::new();
    fh.read_to_string(&mut contents).unwrap();
    drop(fh);

    Ok(contents)
}

/// Read piped input before unlocking or making any network request.
pub fn read_stdin(allow_empty: bool) -> Result<Option<String>> {
    if std::io::stdin().is_terminal() {
        return Ok(None);
    }
    let contents = std::io::read_to_string(std::io::stdin())
        .map_err(|err| Error::FailedToReadFromStdin { err })?;
    validate_stdin(&contents, allow_empty)?;
    Ok(Some(contents))
}

fn validate_stdin(contents: &str, allow_empty: bool) -> Result<()> {
    if !allow_empty && contents.trim().is_empty() {
        return Err(Error::EmptyStdinEdit);
    }
    Ok(())
}

/// `add` stdin is a password, not the editor's password-plus-notes document.
/// Reject ambiguous input before unlocking so no caller can silently split a key.
pub fn validate_password_stdin(contents: &str) -> Result<()> {
    let value = contents
        .strip_suffix("\r\n")
        .or_else(|| contents.strip_suffix('\n'))
        .unwrap_or(contents);
    if value.contains('\r')
        || value.contains('\n')
        || (value.contains("-----BEGIN ")
            && value.contains("PRIVATE KEY-----"))
    {
        return Err(Error::MultilinePasswordStdin);
    }
    Ok(())
}

#[test]
fn single_line_password_stdin_accepts_one_terminal_line_ending() {
    for input in [
        "password",
        "password\n",
        "password\r\n",
        " padded password \n",
    ] {
        assert!(validate_password_stdin(input).is_ok());
    }
}

#[test]
fn multiline_password_stdin_is_rejected_without_exposing_values() {
    for input in [
        "secret-one\nsecret-two\n",
        "secret-one\r\nsecret-two\r\n",
        "secret-one\n\n",
        "secret-one\rsecret-two",
    ] {
        let message = validate_password_stdin(input).unwrap_err().to_string();
        assert!(message.contains("nothing was written"));
        assert!(!message.contains("secret-one"));
        assert!(!message.contains("secret-two"));
    }
}

#[test]
fn private_key_header_cannot_be_stored_as_a_truncated_password() {
    for input in [
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "-----BEGIN RSA PRIVATE KEY-----",
    ] {
        assert!(validate_password_stdin(input).is_err());
    }
}

#[test]
fn password_stdin_guard_leaves_empty_value_policy_to_existing_validation() {
    assert!(validate_password_stdin("").is_ok());
    assert!(validate_stdin("", false).is_err());
    assert!(validate_stdin("", true).is_ok());
}

#[test]
fn empty_input_requires_explicit_permission() {
    for input in ["", " ", "\n\t"] {
        assert!(validate_stdin(input, false).is_err());
        assert!(validate_stdin(input, true).is_ok());
    }
    assert!(validate_stdin("password\nnotes", false).is_ok());
}

fn contains_shell_metacharacters(cmd: &std::ffi::OsStr) -> bool {
    cmd.to_str()
        .is_some_and(|s| s.contains(&[' ', '$', '\'', '"'][..]))
}
