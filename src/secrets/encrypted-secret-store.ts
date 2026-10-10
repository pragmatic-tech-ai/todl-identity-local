import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { ISecretStore } from "@pragmatic-tech-ai/todl-identity";

/**
 * In-memory secret store that keeps secrets by reference, encrypted with AES-256-GCM.
 * Blob layout: base64url(iv ‖ tag ‖ ciphertext). The master key is never exposed.
 */
export class EncryptedSecretStore implements ISecretStore
{
    private static readonly Algorithm = "aes-256-gcm";
    private static readonly IvLength = 12;
    private static readonly TagLength = 16;
    private static readonly KeyLength = 32;
    private static readonly PlaintextEncoding = "utf8";
    private static readonly BlobEncoding = "base64url";
    private static readonly KeyEncoding = "base64";
    private static readonly BadKeyMessage = "Master key must be exactly 32 bytes";

    private readonly masterKey: Buffer;
    private readonly entries: Map<string, string>;

    public constructor(masterKey: Buffer, entries: Map<string, string> = new Map<string, string>())
    {
        if (masterKey.length !== EncryptedSecretStore.KeyLength)
        {
            throw new Error(EncryptedSecretStore.BadKeyMessage);
        }
        this.masterKey = Buffer.from(masterKey);
        this.entries = entries;
    }

    public static FromBase64(masterKeyBase64: string): EncryptedSecretStore
    {
        return new EncryptedSecretStore(Buffer.from(masterKeyBase64, EncryptedSecretStore.KeyEncoding));
    }

    public async Get(reference: string): Promise<string | null>
    {
        const blob = this.entries.get(reference);
        if (blob === undefined)
        {
            return null;
        }
        try
        {
            const raw = Buffer.from(blob, EncryptedSecretStore.BlobEncoding);
            const tagStart = EncryptedSecretStore.IvLength;
            const dataStart = tagStart + EncryptedSecretStore.TagLength;
            const iv = raw.subarray(0, tagStart);
            const tag = raw.subarray(tagStart, dataStart);
            const ciphertext = raw.subarray(dataStart);
            const decipher = createDecipheriv(EncryptedSecretStore.Algorithm, this.masterKey, iv);
            decipher.setAuthTag(tag);
            return Buffer.concat([decipher.update(ciphertext), decipher.final()])
                .toString(EncryptedSecretStore.PlaintextEncoding);
        }
        catch
        {
            // Bad auth tag / wrong key / malformed blob: fail closed, no partial plaintext.
            return null;
        }
    }

    public async Put(reference: string, secret: string): Promise<void>
    {
        const iv = randomBytes(EncryptedSecretStore.IvLength);
        const cipher = createCipheriv(EncryptedSecretStore.Algorithm, this.masterKey, iv);
        const ciphertext = Buffer.concat([
            cipher.update(secret, EncryptedSecretStore.PlaintextEncoding),
            cipher.final(),
        ]);
        const tag = cipher.getAuthTag();
        this.entries.set(
            reference,
            Buffer.concat([iv, tag, ciphertext]).toString(EncryptedSecretStore.BlobEncoding));
    }

    public async Delete(reference: string): Promise<void>
    {
        this.entries.delete(reference);
    }
}
