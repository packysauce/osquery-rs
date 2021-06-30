use std::fmt::Debug;
use std::io::{Error as IoError, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use tracing::trace;

pub struct SpyIO<T> {
    inner: T,
    preview: usize,
}

impl SpyIO<TcpStream> {
    #[allow(dead_code)]
    pub fn try_clone(&self) -> Result<Self, IoError> {
        Ok(Self {
            inner: self.inner.try_clone()?,
            preview: self.preview,
        })
    }
}

impl SpyIO<UnixStream> {
    #[allow(dead_code)]
    pub fn try_clone(&self) -> Result<Self, IoError> {
        Ok(Self {
            inner: self.inner.try_clone()?,
            preview: self.preview,
        })
    }
}

impl<T> AsMut<T> for SpyIO<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Debug> Debug for SpyIO<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpyIO")
            .field("inner", &self.inner)
            .field("preview", &self.preview)
            .finish()
    }
}

impl<T: Read + Write> SpyIO<T> {
    #[allow(dead_code)]
    pub(crate) fn new(inner: T, preview: usize) -> Self {
        Self { inner, preview }
    }
}

impl<T: Write + Debug> Write for SpyIO<T> {
    #[tracing::instrument(skip(buf), fields(buf_len = buf.len()))]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let result = match self.inner.write(buf) {
            Ok(bytes) => {
                let warning = (bytes > self.preview).then(|| "(TRUNC!) ").unwrap_or("");
                trace!(
                    "SpyO: write {} bytes: {}{:?}",
                    bytes,
                    warning,
                    &buf[..bytes.min(self.preview)]
                );
                Ok(bytes)
            }
            Err(e) => {
                trace!("SpyO: write error: {}", e);
                Err(e)
            }
        };
        result
    }

    #[tracing::instrument]
    fn flush(&mut self) -> std::io::Result<()> {
        self.flush()
    }
}

impl<T: Read + Debug> Read for SpyIO<T> {
    #[tracing::instrument(skip(buf), fields(buf_len = buf.len()))]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        //let _span = info_span!("spyo::read", buf_len_enter=buf.len()).entered();
        let result = match self.inner.read(buf) {
            Ok(bytes) => {
                let warning = (bytes > self.preview).then(|| "(TRUNC!) ").unwrap_or("");
                trace!(
                    "SpyI: read {} bytes: {}{:?}",
                    bytes,
                    warning,
                    &buf[..bytes.min(self.preview)]
                );
                Ok(bytes)
            }
            Err(e) => {
                trace!("SpyI: read error: {}", e);
                Err(e)
            }
        };
        result
    }
}
