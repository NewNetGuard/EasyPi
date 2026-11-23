import {
  addCustomSource,
  addToBlacklist as addNetProtectionBlacklist,
  addToWhitelist as addNetProtectionWhitelist,
  generateBlocklists,
  getBlacklist as getNetProtectionBlacklist,
  getCustomSources,
  getVerifiedSources,
  getWhitelist as getNetProtectionWhitelist,
  removeCustomSource,
  removeFromBlacklist as removeNetProtectionBlacklist,
  removeFromWhitelist as removeNetProtectionWhitelist,
  setCustomSourceEnabled,
  setVerifiedSourceEnabled,
} from './netProtectionApi'
import { normalizeBlocklists, normalizeDomainEntries } from './guardSecurityMappers'
import type { Blocklist, DomainEntry } from '../types/security'

export const getBlocklists = async (): Promise<Blocklist[]> => {
  try {
    const [verifiedSources, customSources] = await Promise.all([
      getVerifiedSources().catch(() => []),
      getCustomSources().catch(() => []),
    ])
    return normalizeBlocklists([...verifiedSources, ...customSources])
  } catch {
    return []
  }
}

export const updateBlocklists = async () => {
  return await generateBlocklists()
}

export const toggleBlocklist = async (id: string, enabled: boolean) => {
  const blocklists = await getBlocklists()
  const blocklist = blocklists.find((item) => item.id === id)

  if (!blocklist) {
    throw new Error('Blocklist not found')
  }

  if (blocklist.category.startsWith('verified:')) {
    return await setVerifiedSourceEnabled(id, enabled)
  }

  return await setCustomSourceEnabled(id, enabled)
}

export const deleteBlocklist = async (id: string) => {
  const blocklists = await getBlocklists()
  const blocklist = blocklists.find((item) => item.id === id)

  if (!blocklist) {
    throw new Error('Blocklist not found')
  }

  if (blocklist.category.startsWith('verified:')) {
    throw new Error('Verified blocklists cannot be deleted')
  }

  return await removeCustomSource(id)
}

export const refreshBlocklist = async (url: string) => {
  void url
  return await generateBlocklists()
}

export const addBlocklist = async (payload: { name: string; url: string }) => {
  return await addCustomSource({
    url: payload.url,
    name: payload.name,
    format: 'domains',
    user_confirmed_risks: true,
  })
}

export const getWhitelist = async (): Promise<DomainEntry[]> => {
  try {
    const data = await getNetProtectionWhitelist()
    const domains = data?.domains || data || []
    return normalizeDomainEntries(domains, 'wl')
  } catch {
    return []
  }
}

export const addToWhitelist = async (entry: Omit<DomainEntry, 'id' | 'addedAt' | 'hits'>) => {
  return await addNetProtectionWhitelist(entry.domain, entry.comment)
}

export const removeFromWhitelist = async (id: string) => {
  const whitelist = await getWhitelist()
  const index = parseInt(id.replace('wl-', ''))
  const domain = whitelist[index]?.domain
  if (domain) {
    return await removeNetProtectionWhitelist(domain)
  }
  throw new Error('Domain not found')
}

export const getBlacklist = async (): Promise<DomainEntry[]> => {
  try {
    const data = await getNetProtectionBlacklist()
    const domains = data?.domains || data || []
    return normalizeDomainEntries(domains, 'bl')
  } catch {
    return []
  }
}

export const addToBlacklist = async (entry: Omit<DomainEntry, 'id' | 'addedAt' | 'hits'>) => {
  return await addNetProtectionBlacklist(entry.domain, entry.comment)
}

export const removeFromBlacklist = async (id: string) => {
  const blacklist = await getBlacklist()
  const index = parseInt(id.replace('bl-', ''))
  const domain = blacklist[index]?.domain
  if (domain) {
    return await removeNetProtectionBlacklist(domain)
  }
  throw new Error('Domain not found')
}
