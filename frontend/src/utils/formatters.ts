export const bytesToGigabytes = (bytes?: number, decimals = 1): number => {
  if (!bytes || bytes <= 0) return 0
  return parseFloat((bytes / 1024 ** 3).toFixed(decimals))
}

export const formatTemperature = (value?: number | null): string => {
  if (value === null || value === undefined) {
    return '—'
  }
  return `${Math.round(value)}°C`
}
