export interface RoutingConflict {
  code: 'routing_scope_overlap'
  title: string
  message: string
  feature: 'stealth' | 'internet_encryption'
  other_feature: 'stealth' | 'internet_encryption'
  overlap_count: number | null
  requires_confirmation: boolean
}

export function routingConflictFromError(error: any): RoutingConflict | null {
  const detail = error?.response?.data?.detail
  return detail?.code === 'routing_scope_overlap' ? detail as RoutingConflict : null
}

export function apiErrorMessage(error: any, fallback: string): string {
  const detail = error?.response?.data?.detail
  if (typeof detail === 'string' && detail.trim()) return detail
  if (detail?.message && typeof detail.message === 'string') return detail.message
  return fallback
}

export function confirmRoutingConflict(conflict: RoutingConflict): boolean {
  return window.confirm(
    `${conflict.title}\n\n${conflict.message}\n\n` +
    'Continue only if you intentionally want overlapping tunnels. Continue?',
  )
}

export async function withRoutingConflictConfirmation<T>(
  operation: (confirmed: boolean) => Promise<T>,
): Promise<T | undefined> {
  try {
    return await operation(false)
  } catch (error) {
    const conflict = routingConflictFromError(error)
    if (!conflict) throw error
    if (!confirmRoutingConflict(conflict)) return undefined
    return operation(true)
  }
}
