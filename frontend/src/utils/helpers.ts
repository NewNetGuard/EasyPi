export const formatDuration = (seconds?: number | null): string => {
  if (!seconds || seconds <= 0) {
    return '—'
  }

  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const duration: string[] = []

  if (days) duration.push(`${days}d`)
  if (hours) duration.push(`${hours}h`)
  if (!days && minutes) duration.push(`${minutes}m`)
  if (!duration.length) duration.push(`${Math.max(seconds % 60, 1)}s`)

  return duration.slice(0, 2).join(' ')
}

export const formatTimeLabel = (isoDate: string): string => {
  const date = new Date(isoDate)
  if (Number.isNaN(date.getTime())) {
    return ''
  }
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}
