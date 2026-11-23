import { useQuery } from '@tanstack/react-query'

import { getActionPreview, type ActionPreviewId } from '../../api/actionPreview'

export default function useActionPreview(
  actionId: ActionPreviewId | null,
  targetId: string | number | null | undefined,
  enabled = true,
) {
  return useQuery({
    queryKey: ['action-preview', actionId, targetId],
    queryFn: () => getActionPreview(actionId as ActionPreviewId, targetId as string | number),
    enabled: enabled && Boolean(actionId) && Boolean(targetId),
  })
}
