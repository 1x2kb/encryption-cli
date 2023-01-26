use std::{
    fs,
    io::Error,
    path::{Component, Path, PathBuf},
};

pub fn read_file_string(path: impl AsRef<Path>) -> Result<String, Error> {
    fs::read_to_string(path)
}

pub fn read_file_bytes(path: impl AsRef<Path>) -> Result<Vec<u8>, Error> {
    fs::read(path)
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

#[cfg(test)]
mod read_file {
    use std::ffi::OsString;

    use super::{read_file_bytes, read_file_string};

    #[test]
    fn reads_file_to_bytes() {
        let path = "test-files/test-read-file.txt";

        let expected: Vec<u8> = "qwerty".as_bytes().iter().copied().collect();
        let bytes = read_file_bytes(OsString::from(path)).unwrap();

        assert_eq!(expected, bytes);
    }

    #[test]
    fn reads_file_to_string() {
        let path = "test-files/test-read-file.txt";

        let expected = "qwerty";
        let text = read_file_string(OsString::from(path)).unwrap();

        assert_eq!(text, expected);
    }
}

#[cfg(test)]
mod write_file {
    use super::write_file;

    #[test]
    #[ignore]
    fn writes_file() {
        let path = "test-files/test-write-file.txt";

        let data: Vec<u8> = "qwerty".as_bytes().iter().copied().collect();
        let expected = String::from_utf8(data.clone()).unwrap();
        write_file(data, path).unwrap();

        let file_contents = std::fs::read_to_string(path).unwrap();

        assert_eq!(file_contents, expected);
        std::fs::remove_file(path).unwrap();
    }
}
