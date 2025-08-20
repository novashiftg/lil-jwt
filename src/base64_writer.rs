use base64::{prelude::{BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD}, Engine};
use embedded_io::{ErrorType, Write};

pub const BASE64_INPUT_BLOCK_SIZE: usize = 3;
pub const BASE64_OUTPUT_BLOCK_SIZE: usize = 4;

#[derive(Default)]
pub struct Base64UrlBlockEncoder<T> {
    inner: T,
    input_buffer: [u8; BASE64_INPUT_BLOCK_SIZE],
    output_buffer: [u8; BASE64_OUTPUT_BLOCK_SIZE],
    input_position: usize,
    total_bytes_out: usize,
}

impl<T: Write> Base64UrlBlockEncoder<T> {

    // TODO: make the number of blocks generic
    // pub const MAX_BLOCKS: usize = 1;

    // pub const MAX_INPUT_BYTES: usize = {
    //     Self::MAX_BLOCKS * BASE64_INPUT_BLOCK_SIZE
    // };

    // pub const MAX_OUTPUT_BYTES: usize = {
    //     Self::MAX_BLOCKS * BASE64_OUTPUT_BLOCK_SIZE
    // };

    pub fn new(inner: T) -> Self {
        Self {
            inner,
            input_buffer: [0_u8; BASE64_INPUT_BLOCK_SIZE],
            output_buffer: [0_u8; BASE64_OUTPUT_BLOCK_SIZE],
            input_position: 0_usize,
            
            total_bytes_out: 0,
        }
    }

    pub fn finalize(mut self, padding: bool) -> Result<usize, <Self as ErrorType>::Error> {
        if self.input_position > 0 {
            self.encode_final_block(padding)?;
        }
        Ok(self.total_bytes_out)
    }

    fn is_block_ready(&mut self, byte: u8) -> bool {
        self.input_buffer[self.input_position] = byte;
        self.input_position += 1;
        self.input_position == self.input_buffer.len()
    }

    fn encode_final_block(&mut self, padding: bool) -> Result<(), <Self as ErrorType>::Error> {
        let partial_block = self.input_buffer.split_at(self.input_position).0;
        let encoded_len = if padding {
            BASE64_URL_SAFE.encode_slice(partial_block, &mut self.output_buffer).unwrap()
            
        } else {
            BASE64_URL_SAFE_NO_PAD.encode_slice(partial_block, &mut self.output_buffer).unwrap()
        };
        let to_write = self.output_buffer.split_at(encoded_len).0;
        // eprintln!("flushing partial final block data: {}", core::str::from_utf8(to_write).unwrap_or("not utf8 oopsie"));
        self.inner.write_all(to_write)?;
        self.total_bytes_out += to_write.len();
        Ok(())
    }

    fn encode_full_block(&mut self) -> Result<(), <Self as ErrorType>::Error> {
        assert_eq!(BASE64_OUTPUT_BLOCK_SIZE,BASE64_URL_SAFE_NO_PAD.encode_slice(self.input_buffer, &mut self.output_buffer).unwrap());
        self.input_position = 0;
        self.inner.write_all(&self.output_buffer)?;
        self.total_bytes_out += self.output_buffer.len();
        Ok(())
    }
}

impl<T: ErrorType> ErrorType for Base64UrlBlockEncoder<T> {
    type Error = T::Error;
}

impl<T: Write> Write for Base64UrlBlockEncoder<T> {

    // TODO: optimize this
    fn write(&mut self, mut data: &[u8]) -> Result<usize, <Self as ErrorType>::Error> {
        let mut ret = 0;
        while let Some((first, remaining)) = data.split_first() {
            ret +=1;
            if self.is_block_ready(*first) {
                self.encode_full_block()?;
                return Ok(ret);
            }
            data = remaining;
        }
        Ok(ret)
    }

    fn flush(&mut self) -> Result<(), <Self as ErrorType>::Error> {
        self.inner.flush()
    }

}
