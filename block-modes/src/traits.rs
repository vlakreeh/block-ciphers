use block_cipher_trait::{BlockCipher, InvalidKeyLength};
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::Unsigned;

type Array<N> = GenericArray<u8, N>;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// Error for indicating failed unpadding process
pub struct UnpadError;

/// Trait for padding messages divided into blocks
pub trait Padding {
    /// Pads `block` filled with data up to `pos`
    fn pad(block: &mut [u8], pos: usize);

    /// Unpad given `data` by truncating it according to the used padding.
    /// In case of the malformed padding will return `UnpadError`
    fn unpad(data: &[u8]) -> Result<&[u8], UnpadError>;
}

pub trait BlockMode<C: BlockCipher> {
    fn new_with_cipher(cipher: C, iv: &Array<C::BlockSize>) -> Self;
    fn encrypt_block(&mut self, buffer: &mut Array<C::BlockSize>);
    fn decrypt_block(&mut self, buffer: &mut Array<C::BlockSize>);
}

pub trait PadBlockMode<C: BlockCipher, P: Padding>: BlockMode<C> + Sized {
    fn new(key: &Array<C::KeySize>, iv: &Array<C::BlockSize>) -> Self {
        Self::new_with_cipher(C::new(key), iv)
    }

    fn new_varkey(key: &[u8], iv: &Array<C::BlockSize>)
        -> Result<Self, InvalidKeyLength>
    {
        Ok(Self::new_with_cipher(C::new_varkey(key)?, iv))
    }

    fn encrypt(mut self, buffer: &mut [u8], pos: usize) -> &[u8] {
        let bs = C::BlockSize::to_usize();

        assert!(pos < buffer.len());
        assert_eq!(buffer.len() % bs, 0);

        // TODO: optimize, not optimal
        let n = {
            let (nopad, topad) = buffer.split_at_mut(pos - pos % bs);
            self.encrypt_nopad(nopad);

            P::pad(topad, pos % bs);
            self.encrypt_nopad(topad);
            nopad.len() + topad.len()
        };
        &buffer[..n]
    }

    fn decrypt(mut self, buffer: &mut [u8]) -> Result<&[u8], UnpadError> {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);
        for block in
        self.decrypt_block(buffer);
        P::unpad(buffer)
    }
}
