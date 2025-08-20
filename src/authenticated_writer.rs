use embedded_io::{ErrorType, Write};
use hmac::{digest::{self, CtOutput, Update}, Mac};

pub struct AuthenticatedWriter<T, D> {
    digest: D,
    output: T,
}

impl<T,D> AuthenticatedWriter<T,D> {
    pub fn new(output: T, digest: D) -> Self {
        AuthenticatedWriter { digest, output }
    }
}

impl<T: ErrorType,D> ErrorType for AuthenticatedWriter<T,D> {
    type Error = T::Error;
}

impl<T: Write,D: digest::Update> Write for AuthenticatedWriter<T,D> {
    fn flush(&mut self) -> Result<(), <Self as ErrorType>::Error> {
        self.output.flush()
    }
    fn write(&mut self, data: &[u8]) -> Result<usize, <Self as ErrorType>::Error> {
        let n = self.output.write(data)?;
        self.digest.update(data.split_at(n).0);
        Ok(n)
    }
}

impl<T: Write,D: Mac> AuthenticatedWriter<T,D> {
    pub fn finalize_mac(self) -> CtOutput<D> {
        self.digest.finalize()
    }
}
