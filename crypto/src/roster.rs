//! Member certificates and roster verification.
//!
//! The server relays the roster but can't be trusted to tell the truth about
//! it: it could add a device of its own and post as a "member". So every
//! device in the roster carries a certificate signed by a Key Master, and
//! clients only believe devices whose certificate chains back to a Key Master
//! signing key they pinned themselves (an *anchor*, checked by safety code).
//!
//! A certificate with role `keymaster` makes its device an issuer too, which is
//! how a promotion works: it only counts if an existing, verified Key Master
//! signed it. A member can't certify anyone, including promoting itself.

use crate::{protocol, sign, verify, DeviceKeys, PUBLIC_KEY_LEN};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Member,
    Keymaster,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Member => "member",
            Role::Keymaster => "keymaster",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "member" => Some(Role::Member),
            "keymaster" => Some(Role::Keymaster),
            _ => None,
        }
    }
}

/// One Key Master's statement about one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberCert {
    pub group_id: String,
    pub member_id: String,
    pub device_id: String,
    pub display_name: String,
    pub role: Role,
    pub enc_pk: [u8; PUBLIC_KEY_LEN],
    pub sign_pk: [u8; PUBLIC_KEY_LEN],
    pub issuer_device_id: String,
    pub signature: Vec<u8>,
}

/// The fields a Key Master vouches for, before signing.
#[derive(Debug, Clone)]
pub struct CertSubject<'a> {
    pub group_id: &'a str,
    pub member_id: &'a str,
    pub device_id: &'a str,
    pub display_name: &'a str,
    pub role: Role,
    pub enc_pk: [u8; PUBLIC_KEY_LEN],
    pub sign_pk: [u8; PUBLIC_KEY_LEN],
}

impl MemberCert {
    /// Sign a certificate for `subject` with the issuing Key Master's device keys.
    pub fn issue(issuer: &DeviceKeys, issuer_device_id: &str, subject: &CertSubject) -> MemberCert {
        let mut cert = MemberCert {
            group_id: subject.group_id.to_string(),
            member_id: subject.member_id.to_string(),
            device_id: subject.device_id.to_string(),
            display_name: subject.display_name.to_string(),
            role: subject.role,
            enc_pk: subject.enc_pk,
            sign_pk: subject.sign_pk,
            issuer_device_id: issuer_device_id.to_string(),
            signature: Vec::new(),
        };
        cert.signature = sign(issuer, &cert.message()).to_vec();
        cert
    }

    pub fn message(&self) -> Vec<u8> {
        protocol::member_cert_message(
            &self.group_id,
            &self.member_id,
            &self.device_id,
            &self.display_name,
            self.role.as_str(),
            &self.enc_pk,
            &self.sign_pk,
            &self.issuer_device_id,
        )
    }
}

/// A Key Master signing key this client pinned itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub device_id: String,
    pub sign_pk: [u8; PUBLIC_KEY_LEN],
}

/// A roster entry that passed verification. Use these fields, not the server's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDevice {
    pub member_id: String,
    pub device_id: String,
    pub display_name: String,
    pub role: Role,
    pub enc_pk: [u8; PUBLIC_KEY_LEN],
    pub sign_pk: [u8; PUBLIC_KEY_LEN],
    /// Which Key Master's certificate established `role`.
    pub issuer_device_id: String,
}

/// Work out which devices to believe, from the anchors and every certificate
/// the server handed over. Devices with no valid certificate are simply absent.
///
/// A certificate is valid when it's for `group_id` and its signature verifies
/// under its issuer's key, where the issuer is an anchor or a device that
/// already has a valid `keymaster` certificate. This repeats until nothing new
/// is accepted, so promotion chains of any length work. If valid certificates
/// disagree about a device's member or keys, the device is dropped.
pub fn verify_roster(group_id: &str, anchors: &[Anchor], certs: &[MemberCert]) -> BTreeMap<String, VerifiedDevice> {
    let anchor_keys: BTreeMap<&str, [u8; 32]> = anchors.iter().map(|a| (a.device_id.as_str(), a.sign_pk)).collect();
    let mut accepted: BTreeSet<usize> = BTreeSet::new();
    let mut verified = BTreeMap::new();
    loop {
        let issuers = issuer_keys(&anchor_keys, &verified);
        let mut grew = false;
        for (i, c) in certs.iter().enumerate() {
            if accepted.contains(&i) || c.group_id != group_id {
                continue;
            }
            let Some(key) = issuers.get(c.issuer_device_id.as_str()) else { continue };
            if verify(key, &c.message(), &c.signature).is_ok() {
                accepted.insert(i);
                grew = true;
            }
        }
        verified = resolve(certs, &accepted);
        if !grew {
            return verified;
        }
    }
}

fn issuer_keys<'a>(
    anchors: &BTreeMap<&'a str, [u8; 32]>,
    verified: &'a BTreeMap<String, VerifiedDevice>,
) -> BTreeMap<&'a str, [u8; 32]> {
    let mut keys = anchors.clone();
    for d in verified.values().filter(|d| d.role == Role::Keymaster) {
        // An anchor's pinned key wins over anything a certificate says about it.
        keys.entry(d.device_id.as_str()).or_insert(d.sign_pk);
    }
    keys
}

/// Merge the accepted certificates per device: highest role wins; any
/// disagreement on member or keys drops the device.
fn resolve(certs: &[MemberCert], accepted: &BTreeSet<usize>) -> BTreeMap<String, VerifiedDevice> {
    let mut out: BTreeMap<String, VerifiedDevice> = BTreeMap::new();
    let mut conflicted: BTreeSet<String> = BTreeSet::new();
    for c in accepted.iter().map(|&i| &certs[i]) {
        match out.get_mut(&c.device_id) {
            None => {
                out.insert(
                    c.device_id.clone(),
                    VerifiedDevice {
                        member_id: c.member_id.clone(),
                        device_id: c.device_id.clone(),
                        display_name: c.display_name.clone(),
                        role: c.role,
                        enc_pk: c.enc_pk,
                        sign_pk: c.sign_pk,
                        issuer_device_id: c.issuer_device_id.clone(),
                    },
                );
            }
            Some(d) => {
                if d.member_id != c.member_id || d.enc_pk != c.enc_pk || d.sign_pk != c.sign_pk {
                    conflicted.insert(c.device_id.clone());
                } else if c.role > d.role {
                    d.role = c.role;
                    d.display_name = c.display_name.clone();
                    d.issuer_device_id = c.issuer_device_id.clone();
                }
            }
        }
    }
    for id in conflicted {
        out.remove(&id);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_device_keys;

    const G: &str = "g_test_group";

    struct Dev {
        id: &'static str,
        member: &'static str,
        name: &'static str,
        keys: DeviceKeys,
    }

    fn dev(id: &'static str, member: &'static str, name: &'static str) -> Dev {
        Dev { id, member, name, keys: generate_device_keys() }
    }

    fn subject<'a>(d: &'a Dev, role: Role) -> CertSubject<'a> {
        let p = d.keys.public();
        CertSubject {
            group_id: G,
            member_id: d.member,
            device_id: d.id,
            display_name: d.name,
            role,
            enc_pk: p.enc,
            sign_pk: p.sign,
        }
    }

    fn cert(issuer: &Dev, d: &Dev, role: Role) -> MemberCert {
        MemberCert::issue(&issuer.keys, issuer.id, &subject(d, role))
    }

    fn anchor(d: &Dev) -> Anchor {
        Anchor { device_id: d.id.into(), sign_pk: d.keys.public().sign }
    }

    /// Founder James (self-certified), member Ana certified by James.
    fn group() -> (Dev, Dev, Vec<MemberCert>) {
        let james = dev("d_james", "m_james", "James");
        let ana = dev("d_ana", "m_ana", "Ana");
        let certs = vec![cert(&james, &james, Role::Keymaster), cert(&james, &ana, Role::Member)];
        (james, ana, certs)
    }

    #[test]
    fn founder_and_member_verify_from_the_founder_anchor() {
        let (james, ana, certs) = group();
        let v = verify_roster(G, &[anchor(&james)], &certs);
        assert_eq!(v.len(), 2);
        assert_eq!(v["d_james"].role, Role::Keymaster);
        assert_eq!(v["d_ana"].role, Role::Member);
        assert_eq!(v["d_ana"].sign_pk, ana.keys.public().sign);
        assert_eq!(v["d_ana"].display_name, "Ana");
    }

    #[test]
    fn no_anchors_means_nobody() {
        let (_, _, certs) = group();
        assert!(verify_roster(G, &[], &certs).is_empty());
    }

    #[test]
    fn device_without_a_cert_is_absent() {
        let (james, _, certs) = group();
        // Server injected "mallory" into the roster but has no certificate for it.
        let v = verify_roster(G, &[anchor(&james)], &certs);
        assert!(!v.contains_key("d_mallory"));
    }

    #[test]
    fn forged_signature_is_rejected() {
        let (james, _, mut certs) = group();
        let mallory = dev("d_mallory", "m_mallory", "Mallory");
        let mut forged = cert(&james, &mallory, Role::Member);
        forged.signature[0] ^= 1;
        certs.push(forged);
        let v = verify_roster(G, &[anchor(&james)], &certs);
        assert!(!v.contains_key("d_mallory"));
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn cert_signed_by_the_server_claiming_to_be_the_founder_is_rejected() {
        let (james, _, mut certs) = group();
        let server = dev("d_server", "m_server", "Server");
        let mallory = dev("d_mallory", "m_mallory", "Mallory");
        // Signed with the server's own key but labelled as issued by James.
        certs.push(MemberCert::issue(&server.keys, james.id, &subject(&mallory, Role::Keymaster)));
        let v = verify_roster(G, &[anchor(&james)], &certs);
        assert!(!v.contains_key("d_mallory"));
    }

    #[test]
    fn server_cannot_substitute_an_anchors_key() {
        let (james, _, mut certs) = group();
        let fake = dev("d_james", "m_james", "James");
        // A self-signed "James" cert with a different key, plus a member it vouches for.
        let mallory = dev("d_mallory", "m_mallory", "Mallory");
        certs.push(cert(&fake, &fake, Role::Keymaster));
        certs.push(cert(&fake, &mallory, Role::Member));
        let v = verify_roster(G, &[anchor(&james)], &certs);
        assert!(!v.contains_key("d_mallory"));
        assert_eq!(v["d_james"].sign_pk, james.keys.public().sign);
    }

    #[test]
    fn members_cannot_certify_or_promote() {
        let (james, ana, mut certs) = group();
        let mallory = dev("d_mallory", "m_mallory", "Mallory");
        certs.push(cert(&ana, &mallory, Role::Member));
        certs.push(cert(&ana, &ana, Role::Keymaster));
        let v = verify_roster(G, &[anchor(&james)], &certs);
        assert!(!v.contains_key("d_mallory"));
        assert_eq!(v["d_ana"].role, Role::Member);
    }

    #[test]
    fn promotion_signed_by_a_keymaster_makes_an_issuer() {
        let (james, ana, mut certs) = group();
        let cy = dev("d_cy", "m_cy", "Cy");
        certs.push(cert(&james, &ana, Role::Keymaster));
        certs.push(cert(&ana, &cy, Role::Member));
        let v = verify_roster(G, &[anchor(&james)], &certs);
        assert_eq!(v["d_ana"].role, Role::Keymaster);
        assert_eq!(v["d_ana"].issuer_device_id, "d_james");
        assert_eq!(v["d_cy"].role, Role::Member);
    }

    #[test]
    fn device_approved_by_a_promoted_keymaster_sees_the_founder_via_handed_over_anchors() {
        let (james, ana, mut certs) = group();
        let cy = dev("d_cy", "m_cy", "Cy");
        certs.push(cert(&james, &ana, Role::Keymaster));
        certs.push(cert(&ana, &cy, Role::Member));
        // Cy pinned only Ana: James's self-signed cert doesn't verify.
        let only_ana = verify_roster(G, &[anchor(&ana)], &certs);
        assert!(!only_ana.contains_key("d_james"));
        // With the anchors Ana handed over (Ana + James), everyone verifies.
        let v = verify_roster(G, &[anchor(&ana), anchor(&james)], &certs);
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn edited_fields_break_the_cert() {
        let (james, _, certs) = group();
        let tweaks: Vec<fn(&mut MemberCert)> = vec![
            |c| c.display_name = "Anna".into(),
            |c| c.role = Role::Keymaster,
            |c| c.member_id = "m_james".into(),
            |c| c.enc_pk[0] ^= 1,
            |c| c.sign_pk[0] ^= 1,
            |c| c.signature[63] ^= 1,
        ];
        for tweak in tweaks {
            let mut c = certs.clone();
            tweak(&mut c[1]);
            let v = verify_roster(G, &[anchor(&james)], &c);
            assert!(!v.contains_key("d_ana"), "{:?}", c[1]);
            assert!(v.contains_key("d_james"));
        }
    }

    #[test]
    fn wrong_group_is_rejected() {
        let (james, _, certs) = group();
        assert!(verify_roster("g_other", &[anchor(&james)], &certs).is_empty());
    }

    #[test]
    fn conflicting_valid_certs_drop_the_device() {
        let (james, _, mut certs) = group();
        let other_keys = dev("d_ana", "m_ana", "Ana");
        certs.push(cert(&james, &other_keys, Role::Member));
        let v = verify_roster(G, &[anchor(&james)], &certs);
        assert!(!v.contains_key("d_ana"));
    }
}
