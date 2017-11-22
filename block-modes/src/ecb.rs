use block_cipher_trait::BlockCipher;
use traits::BlockMode;
use block_cipher_trait::generic_array::GenericArray;

pub struct Ecb<C: BlockCipher> {
    cipher: C
}

impl<C: BlockCipher> BlockMode<C> for Ecb<C> {
    fn new_with_cipher(cipher: C, _: &GenericArray<u8, C::BlockSize>) -> Self {
        Self { cipher }
    }

    fn encrypt_nopad(&mut self, buffer: &mut [u8]) {
        self.cipher.encrypt_blocks(buffer).unwrap();
    }

    fn decrypt_nopad(&mut self, buffer: &mut [u8]) {
        self.cipher.decrypt_blocks(buffer).unwrap();
    }
}
