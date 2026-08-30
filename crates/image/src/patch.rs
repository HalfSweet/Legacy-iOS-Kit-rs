use std::io::{Cursor, Read};

use bzip2_rs::DecoderReader;
use thiserror::Error;

const HEADER_SIZE: usize = 32;

pub fn apply_bsdiff(old: &[u8], patch: &[u8]) -> Result<Vec<u8>, PatchError> {
    if patch.len() < HEADER_SIZE || &patch[..8] != b"BSDIFF40" {
        return Err(PatchError::InvalidHeader);
    }
    let control_size = positive_size(&patch[8..16])?;
    let diff_size = positive_size(&patch[16..24])?;
    let new_size = positive_size(&patch[24..32])?;
    let diff_start = HEADER_SIZE
        .checked_add(control_size)
        .ok_or(PatchError::InvalidLayout)?;
    let extra_start = diff_start
        .checked_add(diff_size)
        .ok_or(PatchError::InvalidLayout)?;
    if extra_start > patch.len() {
        return Err(PatchError::InvalidLayout);
    }

    let control = decompress(&patch[HEADER_SIZE..diff_start])?;
    let diff = decompress(&patch[diff_start..extra_start])?;
    let extra = decompress(&patch[extra_start..])?;
    apply_blocks(old, &control, &diff, &extra, new_size)
}

fn apply_blocks(
    old: &[u8],
    control: &[u8],
    diff: &[u8],
    extra: &[u8],
    new_size: usize,
) -> Result<Vec<u8>, PatchError> {
    let mut output = vec![0; new_size];
    let mut control = Cursor::new(control);
    let mut diff_position = 0_usize;
    let mut extra_position = 0_usize;
    let mut old_position = 0_i64;
    let mut new_position = 0_usize;

    while new_position < new_size {
        let add_size = read_offset(&mut control)?;
        let copy_size = read_offset(&mut control)?;
        let seek = read_offset(&mut control)?;
        let add_size = usize::try_from(add_size).map_err(|_| PatchError::InvalidControl)?;
        let copy_size = usize::try_from(copy_size).map_err(|_| PatchError::InvalidControl)?;

        let add_end = new_position
            .checked_add(add_size)
            .ok_or(PatchError::InvalidControl)?;
        let diff_end = diff_position
            .checked_add(add_size)
            .ok_or(PatchError::InvalidControl)?;
        if add_end > new_size || diff_end > diff.len() {
            return Err(PatchError::InvalidControl);
        }
        for index in 0..add_size {
            let old_index = old_position + index as i64;
            let old_byte = usize::try_from(old_index)
                .ok()
                .and_then(|index| old.get(index))
                .copied()
                .unwrap_or(0);
            output[new_position + index] = diff[diff_position + index].wrapping_add(old_byte);
        }
        new_position = add_end;
        diff_position = diff_end;
        old_position += add_size as i64;

        let copy_end = new_position
            .checked_add(copy_size)
            .ok_or(PatchError::InvalidControl)?;
        let extra_end = extra_position
            .checked_add(copy_size)
            .ok_or(PatchError::InvalidControl)?;
        if copy_end > new_size || extra_end > extra.len() {
            return Err(PatchError::InvalidControl);
        }
        output[new_position..copy_end].copy_from_slice(&extra[extra_position..extra_end]);
        new_position = copy_end;
        extra_position = extra_end;
        old_position = old_position
            .checked_add(seek)
            .ok_or(PatchError::InvalidControl)?;
    }

    Ok(output)
}

fn decompress(data: &[u8]) -> Result<Vec<u8>, PatchError> {
    let mut decoder = DecoderReader::new(Cursor::new(data));
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    Ok(output)
}

fn positive_size(bytes: &[u8]) -> Result<usize, PatchError> {
    let value = decode_offset(bytes)?;
    usize::try_from(value).map_err(|_| PatchError::InvalidLayout)
}

fn read_offset(reader: &mut Cursor<&[u8]>) -> Result<i64, PatchError> {
    let mut bytes = [0; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| PatchError::InvalidControl)?;
    decode_offset(&bytes)
}

fn decode_offset(bytes: &[u8]) -> Result<i64, PatchError> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| PatchError::InvalidHeader)?;
    let mut value = i64::from(bytes[7] & 0x7f);
    for byte in bytes[..7].iter().rev() {
        value = value.checked_mul(256).ok_or(PatchError::InvalidLayout)?;
        value = value
            .checked_add(i64::from(*byte))
            .ok_or(PatchError::InvalidLayout)?;
    }
    if bytes[7] & 0x80 != 0 {
        Ok(-value)
    } else {
        Ok(value)
    }
}

#[derive(Debug, Error)]
pub enum PatchError {
    #[error("invalid BSDIFF40 header")]
    InvalidHeader,
    #[error("invalid BSDIFF40 block layout")]
    InvalidLayout,
    #[error("invalid BSDIFF40 control stream")]
    InvalidControl,
    #[error("failed to decompress BSDIFF40 block: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_bsdiff40_patch() {
        let patch = hex::decode(concat!(
            "42534449464634302a0000000000000027000000000000000400000000000000",
            "425a6839314159265359d0149a29000004c0006808200030cd34193f5209593c5d",
            "c914e14243405268a4425a6839314159265359bd1ca64a000000e0004000010020",
            "002100828c5dc914e14242f4729928425a68393141592653592d15eb1c00000010",
            "002000200021184682ee48a70a1205a2bd6380"
        ))
        .unwrap();

        assert_eq!(apply_bsdiff(b"abc", &patch).unwrap(), b"axc!");
    }
}
