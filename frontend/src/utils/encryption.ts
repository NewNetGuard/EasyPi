/**
 * EasyPi client-side file encryption.
 * EPEC v2 encrypts metadata, processes file data in chunks and pads its size.
 * Legacy EPEC v1 files remain decryptable.
 */

const MAGIC_BYTES = new Uint8Array([0x45, 0x50, 0x45, 0x43]) // EPEC
const VERSION_V1 = 1
const VERSION_V2 = 2
const SALT_LENGTH = 16
const V1_IV_LENGTH = 12
const V1_ITERATIONS = 100_000
const V1_HEADER_LENGTH = MAGIC_BYTES.length + 1 + SALT_LENGTH + V1_IV_LENGTH
const V2_ITERATIONS = 600_000
const V2_NONCE_PREFIX_LENGTH = 8
const V2_CHUNK_SIZE = 1024 * 1024
const V2_PADDING_BUCKET = 64 * 1024
const V2_HEADER_LENGTH = MAGIC_BYTES.length + 1 + 4 + SALT_LENGTH + V2_NONCE_PREFIX_LENGTH + 4
const RECORD_LENGTH_BYTES = 4
const GCM_TAG_LENGTH = 16
const V2_METADATA_PLAINTEXT_SIZE = 4 * 1024
const V2_METADATA_CIPHERTEXT_SIZE = V2_METADATA_PLAINTEXT_SIZE + GCM_TAG_LENGTH
const ENCRYPTION_ENABLED_KEY = 'easypi_cloud_encryption_enabled'
const LEGACY_KEY_HASH_KEY = 'easypi_cloud_key_hash'
let runtimePassword: string | null = null

export interface EncryptionOptions {
  originalName?: string
  originalMime?: string
  originalParentPath?: string
}

export interface EncryptedFileMetadata {
  version: 1 | 2
  originalName: string | null
  originalMime: string
  originalParentPath: string | null
  originalSize: number
}

export interface DecryptedFileResult {
  blob: Blob
  metadata: EncryptedFileMetadata
}

interface V2MetadataPayload {
  format: 'EPEC'
  version: 2
  originalName: string
  originalMime: string
  originalParentPath: string
  originalSize: number
  paddedSize: number
  dataRecords: number
}

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => bytes.slice().buffer as ArrayBuffer

const arraysEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false
  return a.every((value, index) => value === b[index])
}

const writeUint32 = (value: number): Uint8Array => {
  const bytes = new Uint8Array(4)
  new DataView(bytes.buffer).setUint32(0, value, false)
  return bytes
}

const readUint32 = (bytes: Uint8Array, offset = 0): number => {
  if (offset < 0 || offset + 4 > bytes.length) throw new Error('Encrypted file is truncated or corrupted')
  return new DataView(bytes.buffer as ArrayBuffer, bytes.byteOffset + offset, 4).getUint32(0, false)
}

const concatBytes = (...parts: Uint8Array[]): Uint8Array => {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0))
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.length
  }
  return result
}

const randomBytes = (length: number): Uint8Array => {
  const result = new Uint8Array(length)
  for (let offset = 0; offset < result.length; offset += 65_536) {
    crypto.getRandomValues(result.subarray(offset, Math.min(offset + 65_536, result.length)))
  }
  return result
}

const getPassword = (password?: string): string => {
  const value = password || runtimePassword
  if (!value) throw new Error('No encryption password available')
  return value
}

const deriveKey = async (password: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> => {
  const passwordKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'],
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: toArrayBuffer(salt), iterations, hash: 'SHA-256' },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

const recordIv = (prefix: Uint8Array, index: number): Uint8Array =>
  concatBytes(prefix, writeUint32(index))

const recordAad = (header: Uint8Array, index: number, ciphertextLength: number): Uint8Array =>
  concatBytes(header, writeUint32(index), writeUint32(ciphertextLength))

const encryptRecord = async (
  plaintext: Uint8Array,
  key: CryptoKey,
  header: Uint8Array,
  noncePrefix: Uint8Array,
  index: number,
): Promise<Uint8Array> => {
  const ciphertextLength = plaintext.length + GCM_TAG_LENGTH
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(recordIv(noncePrefix, index)),
      additionalData: toArrayBuffer(recordAad(header, index, ciphertextLength)),
    },
    key,
    toArrayBuffer(plaintext),
  )
  const ciphertext = new Uint8Array(encrypted)
  return concatBytes(writeUint32(ciphertext.length), ciphertext)
}

const decryptRecord = async (
  blob: Blob,
  offset: number,
  key: CryptoKey,
  header: Uint8Array,
  noncePrefix: Uint8Array,
  index: number,
  maximumLength: number,
): Promise<{ plaintext: Uint8Array; nextOffset: number }> => {
  if (offset + RECORD_LENGTH_BYTES > blob.size) throw new Error('Encrypted file is truncated or corrupted')
  const lengthBytes = new Uint8Array(await blob.slice(offset, offset + RECORD_LENGTH_BYTES).arrayBuffer())
  const ciphertextLength = readUint32(lengthBytes)
  if (ciphertextLength < GCM_TAG_LENGTH || ciphertextLength > maximumLength) {
    throw new Error('Encrypted file contains an invalid record')
  }
  const ciphertextOffset = offset + RECORD_LENGTH_BYTES
  const nextOffset = ciphertextOffset + ciphertextLength
  if (nextOffset > blob.size) throw new Error('Encrypted file is truncated or corrupted')
  const ciphertext = new Uint8Array(await blob.slice(ciphertextOffset, nextOffset).arrayBuffer())
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(recordIv(noncePrefix, index)),
        additionalData: toArrayBuffer(recordAad(header, index, ciphertextLength)),
      },
      key,
      toArrayBuffer(ciphertext),
    )
    return { plaintext: new Uint8Array(plaintext), nextOffset }
  } catch {
    throw new Error('Decryption failed - incorrect password or corrupted file')
  }
}

export const isEncryptionEnabled = (): boolean =>
  localStorage.getItem(ENCRYPTION_ENABLED_KEY) === 'true'

export const enableEncryption = async (password: string): Promise<void> => {
  if (!password || password.length < 8) throw new Error('Password must be at least 8 characters')
  localStorage.setItem(ENCRYPTION_ENABLED_KEY, 'true')
  localStorage.removeItem(LEGACY_KEY_HASH_KEY)
  runtimePassword = password
}

export const disableEncryption = (): void => {
  localStorage.removeItem(ENCRYPTION_ENABLED_KEY)
  localStorage.removeItem(LEGACY_KEY_HASH_KEY)
  runtimePassword = null
}

export const getEncryptionPassword = (): string | null => runtimePassword
export const setEncryptionPassword = (password: string): void => { runtimePassword = password }
export const hasEncryptionPassword = (): boolean => runtimePassword !== null

const buildV2Header = (salt: Uint8Array, noncePrefix: Uint8Array): Uint8Array => {
  const header = new Uint8Array(V2_HEADER_LENGTH)
  header.set(MAGIC_BYTES, 0)
  header[MAGIC_BYTES.length] = VERSION_V2
  header.set(writeUint32(V2_ITERATIONS), 5)
  header.set(salt, 9)
  header.set(noncePrefix, 25)
  header.set(writeUint32(V2_CHUNK_SIZE), 33)
  return header
}

export const encryptFile = async (
  file: File | Blob,
  password?: string,
  options: EncryptionOptions = {},
): Promise<Blob> => {
  const pwd = getPassword(password)
  const salt = randomBytes(SALT_LENGTH)
  const noncePrefix = randomBytes(V2_NONCE_PREFIX_LENGTH)
  const header = buildV2Header(salt, noncePrefix)
  const key = await deriveKey(pwd, salt, V2_ITERATIONS)
  const paddedSize = Math.ceil(Math.max(file.size, 1) / V2_PADDING_BUCKET) * V2_PADDING_BUCKET
  const dataRecords = Math.ceil(paddedSize / V2_CHUNK_SIZE)
  const sourceName = file instanceof File ? file.name : ''
  const sourceMime = file.type || 'application/octet-stream'
  const metadata: V2MetadataPayload = {
    format: 'EPEC',
    version: 2,
    originalName: options.originalName ?? sourceName,
    originalMime: options.originalMime || sourceMime,
    originalParentPath: options.originalParentPath || '/',
    originalSize: file.size,
    paddedSize,
    dataRecords,
  }
  const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata))
  if (metadataBytes.length > V2_METADATA_PLAINTEXT_SIZE - 4) {
    throw new Error('File metadata is too large to encrypt')
  }
  const paddedMetadata = randomBytes(V2_METADATA_PLAINTEXT_SIZE)
  paddedMetadata.set(writeUint32(metadataBytes.length), 0)
  paddedMetadata.set(metadataBytes, 4)
  const parts: BlobPart[] = [toArrayBuffer(header)]
  parts.push(toArrayBuffer(await encryptRecord(paddedMetadata, key, header, noncePrefix, 0)))
  for (let index = 0; index < dataRecords; index += 1) {
    const paddedOffset = index * V2_CHUNK_SIZE
    const plaintextLength = Math.min(V2_CHUNK_SIZE, paddedSize - paddedOffset)
    const plaintext = randomBytes(plaintextLength)
    if (paddedOffset < file.size) {
      const sourceEnd = Math.min(file.size, paddedOffset + plaintextLength)
      plaintext.set(new Uint8Array(await file.slice(paddedOffset, sourceEnd).arrayBuffer()), 0)
    }
    parts.push(toArrayBuffer(await encryptRecord(plaintext, key, header, noncePrefix, index + 1)))
  }
  return new Blob(parts, { type: 'application/octet-stream' })
}

const decryptV1 = async (blob: Blob, originalMime: string, password: string): Promise<DecryptedFileResult> => {
  if (blob.size < V1_HEADER_LENGTH + GCM_TAG_LENGTH) throw new Error('Encrypted file is truncated or corrupted')
  const data = new Uint8Array(await blob.arrayBuffer())
  const salt = data.slice(5, 5 + SALT_LENGTH)
  const iv = data.slice(5 + SALT_LENGTH, V1_HEADER_LENGTH)
  const key = await deriveKey(password, salt, V1_ITERATIONS)
  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(iv) }, key, toArrayBuffer(data.slice(V1_HEADER_LENGTH)),
    )
    const result = new Blob([decrypted], { type: originalMime || 'application/octet-stream' })
    return {
      blob: result,
      metadata: {
        version: 1,
        originalName: null,
        originalMime: result.type,
        originalParentPath: null,
        originalSize: result.size,
      },
    }
  } catch {
    throw new Error('Decryption failed - incorrect password or corrupted file')
  }
}

const parseV2Metadata = (bytes: Uint8Array): V2MetadataPayload => {
  try {
    if (bytes.length !== V2_METADATA_PLAINTEXT_SIZE) throw new Error('invalid metadata size')
    const jsonLength = readUint32(bytes)
    if (jsonLength < 2 || jsonLength > bytes.length - 4) throw new Error('invalid metadata length')
    const jsonBytes = bytes.slice(4, 4 + jsonLength)
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(jsonBytes)) as Partial<V2MetadataPayload>
    const valid = value.format === 'EPEC' && value.version === 2 &&
      typeof value.originalName === 'string' && typeof value.originalMime === 'string' &&
      typeof value.originalParentPath === 'string' && Number.isSafeInteger(value.originalSize) &&
      Number.isSafeInteger(value.paddedSize) && Number.isSafeInteger(value.dataRecords) &&
      (value.originalSize as number) >= 0 && (value.paddedSize as number) >= Math.max(value.originalSize as number, 1) &&
      (value.paddedSize as number) % V2_PADDING_BUCKET === 0 && (value.dataRecords as number) > 0 &&
      Math.ceil((value.paddedSize as number) / V2_CHUNK_SIZE) === value.dataRecords
    if (!valid) throw new Error('invalid metadata')
    return value as V2MetadataPayload
  } catch {
    throw new Error('Encrypted file metadata is corrupted')
  }
}

const decryptV2 = async (blob: Blob, password: string): Promise<DecryptedFileResult> => {
  if (blob.size < V2_HEADER_LENGTH + RECORD_LENGTH_BYTES + GCM_TAG_LENGTH) {
    throw new Error('Encrypted file is truncated or corrupted')
  }
  const header = new Uint8Array(await blob.slice(0, V2_HEADER_LENGTH).arrayBuffer())
  const iterations = readUint32(header, 5)
  const chunkSize = readUint32(header, 33)
  if (iterations !== V2_ITERATIONS || chunkSize !== V2_CHUNK_SIZE) {
    throw new Error('Unsupported or corrupted encryption parameters')
  }
  const salt = header.slice(9, 25)
  const noncePrefix = header.slice(25, 33)
  const key = await deriveKey(password, salt, iterations)
  let offset = V2_HEADER_LENGTH
  const metadataRecord = await decryptRecord(
    blob, offset, key, header, noncePrefix, 0, V2_METADATA_CIPHERTEXT_SIZE,
  )
  offset = metadataRecord.nextOffset
  const metadata = parseV2Metadata(metadataRecord.plaintext)
  const plaintextParts: BlobPart[] = []
  let remaining = metadata.originalSize
  for (let index = 0; index < metadata.dataRecords; index += 1) {
    const expectedLength = Math.min(V2_CHUNK_SIZE, metadata.paddedSize - index * V2_CHUNK_SIZE)
    const record = await decryptRecord(
      blob, offset, key, header, noncePrefix, index + 1, V2_CHUNK_SIZE + GCM_TAG_LENGTH,
    )
    if (record.plaintext.length !== expectedLength) throw new Error('Encrypted file contains an invalid data record')
    offset = record.nextOffset
    const usefulLength = Math.min(remaining, record.plaintext.length)
    if (usefulLength > 0) plaintextParts.push(toArrayBuffer(record.plaintext.slice(0, usefulLength)))
    remaining -= usefulLength
  }
  if (remaining !== 0 || offset !== blob.size) {
    throw new Error('Encrypted file is truncated or contains unexpected data')
  }
  const mime = metadata.originalMime || 'application/octet-stream'
  return {
    blob: new Blob(plaintextParts, { type: mime }),
    metadata: {
      version: 2,
      originalName: metadata.originalName || null,
      originalMime: mime,
      originalParentPath: metadata.originalParentPath || '/',
      originalSize: metadata.originalSize,
    },
  }
}

export const decryptFileWithMetadata = async (
  blob: Blob,
  originalMime = 'application/octet-stream',
  password?: string,
): Promise<DecryptedFileResult> => {
  const pwd = getPassword(password)
  if (blob.size < MAGIC_BYTES.length + 1) throw new Error('Encrypted file is truncated or corrupted')
  const prefix = new Uint8Array(await blob.slice(0, MAGIC_BYTES.length + 1).arrayBuffer())
  if (!arraysEqual(prefix.slice(0, MAGIC_BYTES.length), MAGIC_BYTES)) {
    throw new Error('Invalid encrypted file signature')
  }
  if (prefix[4] === VERSION_V1) return decryptV1(blob, originalMime, pwd)
  if (prefix[4] === VERSION_V2) return decryptV2(blob, pwd)
  throw new Error(`Unsupported encryption version: ${prefix[4]}`)
}

export const decryptFile = async (blob: Blob, originalMime: string, password?: string): Promise<Blob> =>
  (await decryptFileWithMetadata(blob, originalMime, password)).blob

export const isEncryptedFile = async (blob: Blob): Promise<boolean> => {
  if (blob.size < MAGIC_BYTES.length + 1) return false
  const prefix = new Uint8Array(await blob.slice(0, MAGIC_BYTES.length + 1).arrayBuffer())
  return arraysEqual(prefix.slice(0, MAGIC_BYTES.length), MAGIC_BYTES) &&
    (prefix[4] === VERSION_V1 || prefix[4] === VERSION_V2)
}

export const encryptedBlobsEqual = async (expected: Blob, actual: Blob): Promise<boolean> => {
  if (expected.size !== actual.size) return false
  const chunkSize = 1024 * 1024
  for (let offset = 0; offset < expected.size; offset += chunkSize) {
    const end = Math.min(expected.size, offset + chunkSize)
    const left = new Uint8Array(await expected.slice(offset, end).arrayBuffer())
    const right = new Uint8Array(await actual.slice(offset, end).arrayBuffer())
    if (!arraysEqual(left, right)) return false
  }
  return true
}

const ENCRYPTED_FILE_SUFFIX = '.epec'
const MAX_ENCRYPTED_FILENAME_BYTES = 240

const truncateUtf8 = (value: string, maxBytes: number): string => {
  const encoder = new TextEncoder()
  let result = ''
  let byteLength = 0

  for (const character of value) {
    const characterBytes = encoder.encode(character).length
    if (byteLength + characterBytes > maxBytes) break
    result += character
    byteLength += characterBytes
  }

  return result
}

/**
 * Keep the source filename visible while the EPEC payload remains encrypted.
 * The original, untruncated name is also stored inside the authenticated EPEC
 * metadata and is restored when the file is decrypted.
 */
export const encryptedFileNameFor = (originalName: string): string => {
  const leafName = originalName.replace(/\\/g, '/').split('/').pop() || ''
  const cleanName = Array.from(leafName.trim())
    .filter((character) => {
      const codePoint = character.codePointAt(0) ?? 0
      return codePoint >= 32 && codePoint !== 127
    })
    .join('')
  const baseName = cleanName || 'encrypted-file'
  const suffixBytes = new TextEncoder().encode(ENCRYPTED_FILE_SUFFIX).length
  const visibleName = truncateUtf8(baseName, MAX_ENCRYPTED_FILENAME_BYTES - suffixBytes) || 'encrypted-file'
  return `${visibleName}${ENCRYPTED_FILE_SUFFIX}`
}

export const prepareEncryptedUpload = async (
  file: File,
): Promise<{ blob: Blob; encryptedName: string; originalName: string; originalMime: string }> => ({
  blob: await encryptFile(file, undefined, {
    originalName: file.name,
    originalMime: file.type || 'application/octet-stream',
    originalParentPath: '/',
  }),
  encryptedName: encryptedFileNameFor(file.name),
  originalName: file.name,
  originalMime: file.type || 'application/octet-stream',
})

export interface EncryptionStatus {
  enabled: boolean
  hasPassword: boolean
  ready: boolean
}

export const getEncryptionStatus = (): EncryptionStatus => {
  const enabled = isEncryptionEnabled()
  const hasPassword = hasEncryptionPassword()
  return { enabled, hasPassword, ready: enabled && hasPassword }
}
