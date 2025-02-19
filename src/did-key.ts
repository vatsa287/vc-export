import * as Cord from '@cord.network/sdk';
import { encodeAddress } from '@polkadot/util-crypto';
import 'dotenv/config';

const { WEB_URL } = process.env;

export async function convertToDidWeb(did: any) {
    try {
        const didDocument = await resolveDid(did);

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

        didDoc.verificationMethod.push(didDoc.assertionMethod[0]);
        didDoc.verificationMethod[1].type = 'Ed25519VerificationKey2020';
        const assesId = `${id}${didDoc.assertionMethod[0].id}`;
        didDoc.verificationMethod[1].id = assesId;
        didDoc.verificationMethod[1].controller = id;
        didDoc.assertionMethod = [assesId];

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

        return didResponse;
    } catch (error) {
        console.log('error: ', error);
    }
}
