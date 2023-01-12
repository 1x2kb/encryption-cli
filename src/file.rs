use std::{
    fs,
    path::{Component, Path, PathBuf},
};

pub fn read_file_string(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).expect("Failed to read in the private key. Terminating execution")
}

pub fn read_file_bytes(path: impl AsRef<Path>) -> Vec<u8> {
    fs::read(path).expect("Failed to read data file")
}

pub fn write_file(data: Vec<u8>, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
    fs::write(path, data)
}

// Copied from: https://github.com/rust-lang/cargo/blob/fede83ccf973457de319ba6fa0e36ead454d2e20/src/cargo/util/paths.rs#L61
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}
