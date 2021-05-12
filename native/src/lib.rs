use neon::prelude::*;
use neon::result::Throw;
use oberon::*;
use rand::rngs::OsRng;
use std::{
    convert::TryFrom,
    time::{SystemTime, UNIX_EPOCH},
};

macro_rules! slice_to_js_array_buffer {
    ($slice:expr, $cx:expr) => {{
        let mut result = JsArrayBuffer::new(&mut $cx, $slice.len() as u32)?;
        $cx.borrow_mut(&mut result, |d| {
            let bytes = d.as_mut_slice::<u8>();
            bytes.copy_from_slice($slice);
        });
        result
    }};
}

macro_rules! obj_field_to_vec {
    ($cx:expr, $field: expr) => {{
        let v: Vec<Handle<JsValue>> = $cx
            .argument::<JsArray>($field)?
            .to_vec(&mut $cx)?;
        v
    }};
}

/// @param [opt] ArrayBuffer `seed` - An optional seed to create an oberon key pair
/// @returns {
///     "secretKey": ArrayBuffer,
///     "publicKey": ArrayBuffer
/// }
fn new_keys(mut cx: FunctionContext)-> JsResult<JsObject> {
    let sk = match cx.argument_opt(0) {
        Some(seed) => {
            let seed: Handle<JsArrayBuffer> = seed.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
            let seed_data = cx.borrow(&seed, |data| data.as_slice());
            SecretKey::hash(seed_data)
        },
        None => {
            SecretKey::new(OsRng{})
        }
    };
    let pk = PublicKey::from(&sk);

    let sk_bytes = slice_to_js_array_buffer!(&sk.to_bytes(), cx);
    let pk_bytes = slice_to_js_array_buffer!(&pk.to_bytes(), cx);

    let result = JsObject::new(&mut cx);
    result.set(&mut cx, "secretKey", sk_bytes)?;
    result.set(&mut cx, "publicKey", pk_bytes)?;
    Ok(result)
}

/// @param ArrayBuffer `blinding` - A byte array for a blinding factor
/// @returns {
///     "blinding": ArrayBuffer
/// }
fn new_blinding(mut cx: FunctionContext) -> JsResult<JsObject> {
    let blinding: Handle<JsArrayBuffer> = cx.argument(0)?;
    let blinding_data = cx.borrow(&blinding, |data| data.as_slice());
    let bdata = Blinding::new(blinding_data);

    let blinding_bytes = slice_to_js_array_buffer!(&bdata.to_bytes(), cx);

    let result = JsObject::new(&mut cx);
    result.set(&mut cx, "blinding", blinding_bytes)?;
    Ok(result)
}

/// @param ArrayBuffer `id` - The identifier to use for this token
/// @param ArrayBuffer `secretKey` - The secret key used for signing this token
/// @returns {
///     "token": ArrayBuffer
/// }
fn new_token(mut cx: FunctionContext) -> JsResult<JsObject> {
    let id_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;
    let sk_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;

    let id_bytes = cx.borrow(&id_buffer, |data| data.as_slice());
    let sk_bytes = cx.borrow(&sk_buffer, |data| data.as_slice());

    if sk_bytes.len() != SecretKey::BYTES {
        return Err(Throw);
    }

    let sk = SecretKey::from_bytes(&<[u8; SecretKey::BYTES]>::try_from(sk_bytes).unwrap()).unwrap();
    let token = Token::new(&sk, id_bytes).ok_or_else(|| Throw)?;

    let token_bytes = slice_to_js_array_buffer!(&token.to_bytes(), cx);

    let result = JsObject::new(&mut cx);
    result.set(&mut cx, "token", token_bytes)?;
    Ok(result)
}

/// @param ArrayBuffer `token` - The token or blinded token signed by the issuing authority
/// @param ArrayBuffer `blinding` - The blinding factor to apply to the token
/// @returns {
///     "token": ArrayBuffer
/// }
fn blind_token(mut cx: FunctionContext) -> JsResult<JsObject> {
    let token_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;
    let blinding_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;

    let token_bytes = cx.borrow(&token_buffer, |data| data.as_slice());
    let blinding_bytes = cx.borrow(&blinding_buffer, |data| data.as_slice());

    if token_bytes.len() != Token::BYTES ||
        blinding_bytes.len() != Blinding::BYTES {
        return Err(Throw);
    }

    let token = Token::from_bytes(&<[u8; Token::BYTES]>::try_from(token_bytes).unwrap()).unwrap();
    let blinding = Blinding::from_bytes(&<[u8; Blinding::BYTES]>::try_from(blinding_bytes).unwrap()).unwrap();

    let blinded_token = token - blinding;
    let blinded_token_bytes = slice_to_js_array_buffer!(&blinded_token.to_bytes(), cx);

    let result = JsObject::new(&mut cx);
    result.set(&mut cx, "token", blinded_token_bytes)?;
    Ok(result)
}

/// Generates a new proof using the current system timestamp as the nonce
/// @param ArrayBuffer `token` - The token or blinded token for which to generate a proof
/// @param ArrayBuffer `id` - The identifier to use for this token
/// @param Array<ArrayBuffer> `blindings` - All the blindings applied to the token
/// @returns {
///     "proof": ArrayBuffer,
///     "timestamp": ArrayBuffer
/// }
fn new_proof_timestamp(mut cx: FunctionContext) -> JsResult<JsObject> {
    let token_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;
    let id_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;
    let blindings_vec = obj_field_to_vec!(cx, 2);

    let token_bytes = cx.borrow(&token_buffer, |data| data.as_slice());
    if token_bytes.len() != Token::BYTES {
        return Err(Throw);
    }

    let mut blindings = Vec::with_capacity(blindings_vec.len());
    for b in blindings_vec {
        let a = b.downcast::<JsArrayBuffer>().or_throw(&mut cx)?;
        let blinding_bytes = cx.borrow(&a, |data| data.as_slice());

        if blinding_bytes.len() != Blinding::BYTES {
            return Err(Throw);
        }
        let blinding = Blinding::from_bytes(&<[u8; Blinding::BYTES]>::try_from(blinding_bytes).unwrap()).unwrap();
        blindings.push(blinding);
    }

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let timestamp_bytes = timestamp.as_micros().to_be_bytes();
    let token = Token::from_bytes(&<[u8; Token::BYTES]>::try_from(token_bytes).unwrap()).unwrap();
    let id_bytes = cx.borrow(&id_buffer, |data| data.as_slice());

    let proof = Proof::new(&token, blindings.as_slice(), id_bytes, &timestamp_bytes[..], OsRng{}).ok_or_else(|| Throw)?;

    let result = JsObject::new(&mut cx);
    let proof_bytes = slice_to_js_array_buffer!(&proof.to_bytes()[..], cx);
    let timestamp_bytes = slice_to_js_array_buffer!(&timestamp_bytes[..], cx);
    result.set(&mut cx, "proof", proof_bytes)?;
    result.set(&mut cx, "timestamp", timestamp_bytes)?;
    Ok(result)
}

register_module!(mut cx, {
    cx.export_function("newKeys", new_keys)?;
    cx.export_function("newBlinding", new_blinding)?;
    cx.export_function("newToken", new_token)?;
    cx.export_function("blindToken", blind_token)?;
    cx.export_function("newProofTimestamp", new_proof_timestamp)?;
    Ok(())
});
