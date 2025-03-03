# libqaeda

The aim of this library is to enable bi-lateral countersigning of chains of promises and statements.

There are many use-cases to imagine, among which:

* Authenticity and proof-of-ownership of certificates.
* Credit tracking between individuals

See bottom of document for development related information.


## Design 


### Certificate

The highest level construct in the library is the certificate `LQCert`.

It consists of two messages, a request and a response.

The request message is authored  and signed first then transmitted to the responder.

The responder authors its own message, and signed its message together with the signature of the request.

The certificate may optionally be linked to a previous `LQCert`. In this case both the request and response signature are also made over the linked certificate.


#### Certificate domain

An arbirary domain byte string can be defined for each certificate.

This is intended for use at the application level, to decide whether a certificate is relevant, and how to process it.

The domain is also part of the request and response signatures.


### Message

Both the request and response message use the same data structure, the `LQMsg`.

The message contents are stores as a digest of the message itself.

This digest is serialized together with the nanosecond timestamp when the message was created, and the public key that will sign the message. The serialized message is then added to the certificate.


### Resolving content

`libqaeda` defines a key-value store interface, that is embedded into message creation, certificate creation and public key stores.

On message creation, the message contents will be `put` into the store keyed by its digest. This store can be a network store, a local disk, a database, memory - any backend possible to implement.

Once the message is recovered, the same store can be used to `get` the content by the same key.


### Trust handling

One function of a store is to keep a dictionary of public keys and their trust data.

This is used by the application data to decide whether or not a signature belongs to a public key that is known, and how and for what the public key can be trusted.

The trust module allows for a range of behaviors, from only checking whether a public key exists, to trust ratios calculated by matching application defined trust flags.


### Cryptography.

Crypto is defined as an interface.

The aim is to allow for any public-key crypto backend to be implemented. 

Key handling is abstracted by two data structures, `LQPrivKey` and `LQPubKey`. The `LQPubKey` structure may or may not contain the `LQPrivKey`.

Signatures are encapsulated by `LQSig`. This structure must contain the public key, unless the signature implementation allows for keys being recovered from signatures.


### IO handling

Similarly as with the cryptography component, the component for memory handling and io operations only defines an interface.

The aim is to grant greater control to the application author to implement handling for environments like phones, webassembly and so on.


## Development status

**This software is strictly alpha and not safe in any way.**

* File content store currently has hardcoded unix/linux file operation functions.
* Memory and IO currently only implements standard library.
* Currently only contains dummy crypto backend.
* Not threads audited.
* All private keys are currently unencrypted.
* There are probably memory leaks.


### Dependencies

* `libasn1`
* `libcheck` (tests)


### Example code

Please refer to the `src/test` directory. There are no other examples.


## License

The `libqaeda` library is provided under the Affero Gnu Public License 3.0 (`AGPL3`) license.

All documentation is provided under the Creative Commons Attribution Share-alike International 4.0 license (`CC-BY-SA-4.0`).

This repository contains other code sources that may be subject under other licenses. Please see `src/aux` for more details.
