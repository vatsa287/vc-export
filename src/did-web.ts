import * as Cord from '@cord.network/sdk';
import 'dotenv/config';

const { WEB_URL } = process.env;

export async function convertToDidWeb(did: Cord.DidDocument) {
    try {
        let id = did.uri.replace('did:cord', `did:web:${WEB_URL}`);
        return id;
    } catch (error) {
        console.error('error: ', error);
        throw new Error('Did or key not generated');
    }
}
