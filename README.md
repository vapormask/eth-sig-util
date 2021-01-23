# Vap-Sig-Util [![CircleCI](https://circleci.com/gh/Vapormask/vap-sig-util.svg?style=svg)](https://circleci.com/gh/Vapormask/vap-sig-util)

A small collection of vapory signing functions.

You can find usage examples [here](https://github.com/vapormask/js-vap-personal-sign-examples) 

[Available on NPM](https://www.npmjs.com/package/vap-sig-util)

## Supported Signing Methods

Currently there is only one supported signing protocol. More will be added as standardized. 

- Personal Sign (`personal_sign`) [gvap thread](https://github.com/vaporyco/go-vapory/pull/2940)


## Installation

```
npm install vap-sig-util --save
```

## Methods

### concatSig(v, r, s)

All three arguments should be provided as buffers.

Returns a continuous, hex-prefixed hex value for the signature, suitable for inclusion in a JSON transaction's data field.

### normalize(address)

Takes an address of either upper or lower case, with or without a hex prefix, and returns an all-lowercase, hex-prefixed address, suitable for submitting to an vapory provider.

### personalSign (privateKeyBuffer, msgParams)

msgParams should have a `data` key that is hex-encoded data to sign.

Returns the prefixed signature expected for calls to `vap.personalSign`.

### recoverPersonalSignature (msgParams)

msgParams should have a `data` key that is hex-encoded data unsigned, and a `sig` key that is hex-encoded and already signed.

Returns a hex-encoded sender address.

### signTypedData (privateKeyBuffer, msgParams)

Signs typed data as per [EIP712](https://github.com/vaporyco/VIPs/pull/712).

Data should be under `data` key of `msgParams`. The method returns prefixed signature.

### recoverTypedSignature ({data, sig})

Return address of a signer that did `signTypedData`.

Expects the same data that were used for signing. `sig` is a prefixed signature.

### extractPublicKey (msgParams)

msgParams should have a `data` key that is hex-encoded data unsigned, and a `sig` key that is hex-encoded and already signed.

Returns a hex-encoded public key.

