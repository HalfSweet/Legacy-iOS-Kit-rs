use legacy_ios_firmware::{BuildIdentity, FirmwareArchive, FirmwareError};
use legacy_ios_image::{Img3, Img3Error, Img4Error, personalize_img4};
use plist::{Dictionary, Value};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct ComponentPersonalizer {
    archive: FirmwareArchive,
    identity: BuildIdentity,
    tss: Dictionary,
}

impl ComponentPersonalizer {
    pub fn new(archive: FirmwareArchive, identity: BuildIdentity, tss: Dictionary) -> Self {
        Self {
            archive,
            identity,
            tss,
        }
    }

    pub fn root_ticket(&self) -> Option<&[u8]> {
        self.tss
            .get("ApImg4Ticket")
            .or_else(|| self.tss.get("APTicket"))
            .and_then(Value::as_data)
    }

    pub fn personalize(&self, component: &str) -> Result<Vec<u8>, PersonalizationError> {
        let path = self
            .tss
            .get(component)
            .and_then(Value::as_dictionary)
            .and_then(|entry| entry.get("Path"))
            .and_then(Value::as_string)
            .map(ToOwned::to_owned)
            .map_or_else(
                || {
                    self.identity
                        .component_path(component)
                        .map(ToOwned::to_owned)
                },
                Ok,
            )?;
        let data = self.archive.read_entry(&path)?;
        personalize_data(component, data, &self.tss)
    }
}

fn personalize_data(
    component: &str,
    data: Vec<u8>,
    tss: &Dictionary,
) -> Result<Vec<u8>, PersonalizationError> {
    if let Some(ticket) = tss.get("ApImg4Ticket").and_then(Value::as_data) {
        return Ok(personalize_img4(component, &data, ticket)?);
    }
    let blob = tss
        .get(component)
        .and_then(Value::as_dictionary)
        .and_then(|entry| entry.get("Blob"))
        .and_then(Value::as_data);
    if let Some(blob) = blob {
        return Ok(Img3::parse(&data)?.personalize(blob)?.to_bytes());
    }
    Ok(data)
}

#[derive(Debug, Error)]
pub enum PersonalizationError {
    #[error(transparent)]
    Firmware(#[from] FirmwareError),
    #[error(transparent)]
    Img3(#[from] Img3Error),
    #[error(transparent)]
    Img4(#[from] Img4Error),
}

#[cfg(test)]
mod tests {
    use legacy_ios_image::{Img3Element, Img3Tag};

    use super::*;

    #[test]
    fn applies_component_img3_blob() {
        let image = Img3::new(1, vec![Img3Element::new(Img3Tag::DATA, vec![1, 2, 3])]);
        let blob = [
            Img3Element::new(Img3Tag::ECID, vec![1]),
            Img3Element::new(Img3Tag::SHSH, vec![2]),
            Img3Element::new(Img3Tag::CERT, vec![3]),
        ]
        .into_iter()
        .flat_map(|element| {
            let image = Img3::new(0, vec![element]);
            image.to_bytes()[20..].to_vec()
        })
        .collect::<Vec<_>>();
        let mut entry = Dictionary::new();
        entry.insert("Blob".into(), Value::Data(blob));
        let mut tss = Dictionary::new();
        tss.insert("iBSS".into(), entry.into());

        let result = personalize_data("iBSS", image.to_bytes(), &tss).unwrap();
        assert!(Img3::parse(&result).unwrap().is_personalized());
    }
}
