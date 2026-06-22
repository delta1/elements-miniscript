// Example: using translate_pk on a confidential descriptor to go from wildcard
// DescriptorPublicKey keys to concrete DefiniteDescriptorKey keys at a given
// derivation index, then derive a confidential address.

extern crate elements_miniscript as miniscript;

use std::str::FromStr;

use miniscript::{
    confidential, translate_hash_clone, DefiniteDescriptorKey, DescriptorPublicKey, NoExt,
    Translator,
};

struct IndexTranslator(u32);

impl Translator<DescriptorPublicKey, DefiniteDescriptorKey, ()> for IndexTranslator {
    fn pk(&mut self, pk: &DescriptorPublicKey) -> Result<DefiniteDescriptorKey, ()> {
        pk.clone().at_derivation_index(self.0).map_err(|_| ())
    }

    translate_hash_clone!(DescriptorPublicKey, DefiniteDescriptorKey, ());
}

fn main() {
    let secp = elements::secp256k1_zkp::Secp256k1::new();

    // Confidential descriptor: SLIP77 blinding key + wildcard P2WPKH spend key.
    let desc_str = "ct(\
        slip77(b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04),\
        elwpkh(xpub661MyMwAqRbcEcT9W98HZP2kFzyzQQZkYnrRnrM8uD8kH8kSeFoQHq1x2iihLg\
        C6PXGy5LrjCL66uSNhJ8pwjfx2rMUTLWuRMns2EG9xnjs/*))";

    let desc = confidential::Descriptor::<DescriptorPublicKey, NoExt>::from_str(desc_str).unwrap();

    for index in 0..3 {
        let definite: confidential::Descriptor<DefiniteDescriptorKey, NoExt> =
            desc.translate_pk(&mut IndexTranslator(index)).unwrap();

        let conf_addr = definite
            .address(&secp, &elements::AddressParams::LIQUID)
            .unwrap();
        let unconf_addr = definite
            .unconfidential_address(&elements::AddressParams::LIQUID)
            .unwrap();

        println!("index {index}:");
        println!("  confidential:   {conf_addr}");
        println!("  unconfidential: {unconf_addr}");
    }
}
