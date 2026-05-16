
    pub fn payload_encrypt(data : & Vec<u8>) -> Vec<u8> {
        //function returns the new Vec<u8> back 

            use openssl::symm::{encrypt, Cipher};
            use std::fs;


            let key = fs::read("/root/key.txt").unwrap(); //returns vec<u8>
            let mut iv1 = key.clone();
            let iv = iv1.split_off(16);

            let cipher = Cipher::aes_256_ctr();
            //let cipher = Cipher::aes_256_gcm();
            //let cipher = Cipher::bf_cbc();

            //println!("IV Length: {}",iv.len());
            let data_enc = encrypt(cipher, &key, Some(&iv), data).unwrap();

            data_enc
    }



        

    pub fn payload_decrypt(data : & Vec<u8>) -> Vec<u8> {
            use openssl::symm::{decrypt, Cipher};
            use std::fs;

            let key = fs::read("/root/key.txt").unwrap(); //returns vec<u8>
            let mut iv1 = key.clone();

            let iv = iv1.split_off(16);

            let cipher = Cipher::aes_256_ctr();
            //let cipher = Cipher::aes_256_gcm();
            //let cipher = Cipher::bf_cbc();

            //println!("IV Length: {}",iv.len());
            let data_dec = decrypt(cipher, &key, Some(&iv), data).unwrap();
            data_dec
    }


    pub fn keygen()
    {
            use std::fs::File;
            use std::io::Write;
        
            let keybuf = gen_aes256_key();

            let mut fd1 = File::create("/root/key.txt").unwrap();
            fd1.write(&keybuf);
    }






    pub fn gen_aes256_key() -> Vec<u8> {

        use openssl::rand::rand_bytes;

        let mut keybuf = [0; 32];
        rand_bytes(&mut keybuf).unwrap();

        //Returning the 32 bytes key
        keybuf.to_vec()
    }
