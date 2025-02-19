import * as Cord from '@cord.network/sdk';
// import { u8aToHex } from '@cord.network/sdk';
import { encodeAddress } from '@polkadot/util-crypto';
import 'dotenv/config';

const { WEB_URL } = process.env;

// import base58 from 'bs58';
// import {
//     mnemonicToMiniSecret,
//     ed25519PairFromSeed,
// } from '@polkadot/util-crypto';

export async function convertToDidWeb(did: any) {
    try {
        // Convert mnemonic to seed and derive the key pair.
        // const seed = mnemonicToMiniSecret(mnemonic);
        // const { publicKey } = ed25519PairFromSeed(seed);

        // // Generate a multicodec-prefixed public key.
        // // For Ed25519VerificationKey2020, the prefix is 0xed01.
        // const multicodecPrefixedKey = new Uint8Array([
        //     0xed,
        //     0x01,
        //     ...publicKey,
        // ]);
        // const encodedKey = base58.encode(multicodecPrefixedKey);

        // // Construct the did:web identifier.
        // // Note: did:web DIDs are based on the domain (and optional path), not on key material.
        // const domain = `oid4vci.demo.cord.network:${encodedKey}`;
        // let did = `did:web:${domain}`;
        // // if (path) {
        // //     // Replace any "/" with ":" per did:web formatting rules.
        // //     const formattedPath = path.split('/').join(':');
        // //     did += `:${formattedPath}`;
        // // }

        // // Create the verification method identifier by appending the encoded key as a fragment.
        // const verificationMethod = `${did}#z${encodedKey}`;

        // // Construct a basic did:web DID Document.
        // const didDocument = {
        //     '@context': 'https://www.w3.org/ns/did/v1',
        //     id: did,
        //     verificationMethod: [
        //         {
        //             id: verificationMethod,
        //             type: 'Ed25519VerificationKey2020',
        //             controller: did,
        //             publicKeyMultibase: `z${encodedKey}`,
        //         },
        //     ],
        //     authentication: [verificationMethod],
        // };

        const didDocument = await resolveDid(did);
        console.log('Final didDocument: ', didDocument);

        return { didDocument };
    } catch (error) {
        console.error('error: ', error);
        throw new Error('Did or key not generated');
    }
}

export async function resolveDid(did: any) {
    try {
        const didUri = `did:cord:${did.uri.split(':')[2]}`;

        let didDoc = await resolve2Did(didUri);

        let id = didDoc.uri.replace('did:cord', WEB_URL);

        delete didDoc.uri;
        didDoc.id = id;
        didDoc.verificationMethod = didDoc.authentication;
        didDoc.verificationMethod[0].type = 'Ed25519VerificationKey2020';
        const authId = `${id}${didDoc.authentication[0].id}`;
        didDoc.verificationMethod[0].id = authId;
        didDoc.verificationMethod[0].controller = id;
        didDoc.authentication = [authId];

        // delete didDoc.authentication;
        didDoc.verificationMethod.push(didDoc.assertionMethod[0]);
        didDoc.verificationMethod[1].type = 'Ed25519VerificationKey2020';
        const assesId = `${id}${didDoc.assertionMethod[0].id}`;
        didDoc.verificationMethod[1].id = assesId;
        didDoc.verificationMethod[1].controller = id;
        didDoc.assertionMethod = [assesId];
        // delete didDoc.assertionMethod;
        delete didDoc.service;
        delete didDoc.capabilityDelegation;
        delete didDoc.keyAgreement;
        /* fix the publicKey */

        return {
            '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/suites/ed25519-2020/v1',
            ],
            ...didDoc,
        };
    } catch (error) {
        console.log('error: ', error);
    }
}

export async function resolve2Did(didUri: string) {
    try {
        const didDoc = await Cord.Did.resolve(didUri as `did:cord:3${string}`);

        let didResponse: any = { ...didDoc?.document };
        if (didDoc) {
            let a = Cord.u8aToHex(didResponse.assertionMethod[0].publicKey);
            didResponse.assertionMethod[0]!.publicKeyHex = a;
            didResponse.assertionMethod[0]!.publicKeyMultibase =
                'z' + encodeAddress(a);
            delete didResponse.assertionMethod[0]?.publicKey;

            let b = Cord.u8aToHex(didResponse.authentication[0].publicKey);
            didResponse.authentication[0]!.publicKeyHex = b;
            didResponse.authentication[0]!.publicKeyMultibase =
                'z' + encodeAddress(b);
            delete didResponse.authentication[0]?.publicKey;
        }

        console.log('didDoc2: ', didResponse);

        return didResponse;
    } catch (error) {
        console.log('error: ', error);
    }
}
