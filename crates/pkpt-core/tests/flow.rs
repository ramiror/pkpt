use pkpt_core::contact::{self, Update, safety_words};
use pkpt_core::*;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 24 * 3600;

struct Person {
    root: RootKey,
    devices: Vec<DeviceKey>,
    list: SignedDeviceList,
}

fn person(devices: &[&str]) -> Person {
    let (_, root) = RootKey::generate();
    let devices: Vec<_> = devices.iter().map(|n| DeviceKey::generate(*n)).collect();
    let list = root.sign_device_list(1, NOW, devices.iter().map(|d| d.entry()).collect());
    Person { root, devices, list }
}

#[test]
fn phrase_regenerates_same_root() {
    let (phrase, root) = RootKey::generate();
    assert_eq!(phrase.split_whitespace().count(), 24);
    assert_eq!(RootKey::from_phrase(&phrase).unwrap().public(), root.public());
    assert_eq!(
        RootKey::from_phrase("chamuyo de palabras").err(),
        Some(Error::InvalidPhrase)
    );
}

#[test]
fn device_secret_roundtrip() {
    let ramiro = person(&["notebook"]);
    let d = DeviceKey::import(&ramiro.devices[0].export()).unwrap();
    assert_eq!(d.entry(), ramiro.devices[0].entry());
}

#[test]
fn detached_signature() {
    let ramiro = person(&["notebook", "celu"]);
    let sig = DetachedSignature::sign(&ramiro.devices[1], &ramiro.list, b"contrato").unwrap();
    let sig = DetachedSignature::from_armored(&sig.to_armored()).unwrap();

    let v = sig.verify(b"contrato", NOW).unwrap();
    assert_eq!(v.root, ramiro.root.public());
    assert_eq!(v.device_name, "celu");
    assert_eq!(
        sig.verify(b"contrato trucho", NOW).err(),
        Some(Error::BadSignature)
    );
    assert_eq!(
        sig.verify(b"contrato", NOW + 31 * DAY).err(),
        Some(Error::Expired)
    );
}

#[test]
fn device_outside_list_cannot_sign() {
    let ramiro = person(&["notebook"]);
    let intruso = DeviceKey::generate("intruso");
    assert_eq!(
        DetachedSignature::sign(&intruso, &ramiro.list, b"x").err(),
        Some(Error::UnknownDevice)
    );
}

#[test]
fn contact_bech32_roundtrip_case_insensitive() {
    let juana = person(&["celu"]);
    let s = contact::encode(&juana.list).unwrap();
    assert!(s.starts_with("pkpt1"));
    assert_eq!(contact::decode(&s, NOW).unwrap(), juana.list);
    assert_eq!(contact::decode(&s.to_uppercase(), NOW).unwrap(), juana.list);

    let mut typo = s.into_bytes();
    let i = typo.len() / 2;
    typo[i] = if typo[i] == b'q' { b'p' } else { b'q' };
    assert!(contact::decode(std::str::from_utf8(&typo).unwrap(), NOW).is_err());
}

#[test]
fn safety_words_are_stable() {
    let juana = person(&["celu"]);
    let w = safety_words(&juana.root.public());
    assert_eq!(w, safety_words(&juana.root.public()));
    assert_ne!(w, safety_words(&person(&["celu"]).root.public()));
}

#[test]
fn contact_book_is_monotonic() {
    let ramiro = person(&["notebook", "celu"]);
    let mut book = ContactBook::default();
    book.add("Hijo", ramiro.list.clone(), Trust::Verified, NOW)
        .unwrap();

    // Revocación del celu: v2 solo con la notebook.
    let v2 = ramiro
        .root
        .sign_device_list(2, NOW, vec![ramiro.devices[0].entry()]);
    assert_eq!(
        book.observe(&v2, NOW).unwrap(),
        Update::Updated { from: 1, to: 2 }
    );
    assert_eq!(book.observe(&v2, NOW).unwrap(), Update::Unchanged);
    assert_eq!(
        book.observe(&ramiro.list, NOW).err(),
        Some(Error::Stale { have: 2, got: 1 })
    );

    let desconocido = person(&["celu"]);
    assert_eq!(
        book.observe(&desconocido.list, NOW).err(),
        Some(Error::WrongIdentity)
    );
}

#[test]
fn forged_device_list_rejected() {
    let ramiro = person(&["notebook"]);
    let chorro = person(&["celu robado"]);
    let mut forged = chorro
        .root
        .sign_device_list(9, NOW, vec![chorro.devices[0].entry()]);
    forged.list.root = ramiro.root.public();
    assert_eq!(forged.verify(NOW).err(), Some(Error::BadSignature));
}

#[test]
fn encrypt_to_all_recipient_devices() {
    let ramiro = person(&["notebook"]);
    let juana = person(&["celu", "notebook"]);
    let ct = encrypt(&ramiro.devices[0], &ramiro.list, &[&juana.list], b"DNI.pdf", NOW).unwrap();

    for d in &juana.devices {
        let opened = decrypt(d, &juana.root.public(), &ct, NOW).unwrap();
        assert_eq!(opened.plaintext, b"DNI.pdf");
        assert_eq!(opened.signer.root, ramiro.root.public());
        assert_eq!(opened.signer_list, ramiro.list);
    }
    // No se cifra para uno mismo.
    assert!(decrypt(&ramiro.devices[0], &ramiro.root.public(), &ct, NOW).is_err());
}

#[test]
fn revoked_device_cannot_decrypt() {
    let ramiro = person(&["notebook"]);
    let juana = person(&["celu", "notebook"]);
    let v2 = juana
        .root
        .sign_device_list(2, NOW, vec![juana.devices[1].entry()]);
    let ct = encrypt(&ramiro.devices[0], &ramiro.list, &[&v2], b"secreto", NOW).unwrap();
    assert!(decrypt(&juana.devices[0], &juana.root.public(), &ct, NOW).is_err());
    assert!(decrypt(&juana.devices[1], &juana.root.public(), &ct, NOW).is_ok());
}

#[test]
fn expired_recipient_list_refused() {
    let ramiro = person(&["notebook"]);
    let juana = person(&["celu"]);
    let later = NOW + 31 * DAY;
    assert_eq!(
        encrypt(&ramiro.devices[0], &ramiro.list, &[&juana.list], b"x", later).err(),
        Some(Error::Expired)
    );
}

#[test]
fn not_listed_as_recipient_rejected() {
    // Juana recibe algo para ella y quiere hacerlo pasar por dirigido a Pedro.
    // Como el contenido sellado lista a Juana, la app de Pedro lo rechaza.
    let ramiro = person(&["notebook"]);
    let juana = person(&["celu"]);
    let pedro = person(&["celu"]);
    let ct = encrypt(&ramiro.devices[0], &ramiro.list, &[&juana.list], b"x", NOW).unwrap();
    assert_eq!(
        decrypt(&juana.devices[0], &pedro.root.public(), &ct, NOW).err(),
        Some(Error::NotARecipient)
    );
}
