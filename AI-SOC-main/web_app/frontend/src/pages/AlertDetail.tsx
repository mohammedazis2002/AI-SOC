import { useParams, Link } from 'react-router-dom'
import { useAlert, useSimilarAlerts } from '@/hooks/useAlert'
import { ProcessedAlertDetail } from '@/components/alerts/ProcessedAlertDetail'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'

export function AlertDetail() {
  const { id } = useParams<{ id: string }>()
  const decodedId = id ? decodeURIComponent(id) : undefined

  const { data, isLoading, isError, error } = useAlert(decodedId)
  const { data: similarAlerts = [] } = useSimilarAlerts(decodedId)

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="grid lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 space-y-4">
            <Skeleton className="h-40" />
            <Skeleton className="h-32" />
          </div>
          <Skeleton className="h-64" />
        </div>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="space-y-4">
        <p className="text-red-600 text-sm">Failed to load alert: {String((error as Error)?.message ?? error)}</p>
        <Button variant="outline" asChild>
          <Link to="/alerts">Back to Alerts</Link>
        </Button>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="space-y-4">
        <p className="text-slate-600">No alert found for ID {decodedId ? <span className="font-mono">{decodedId}</span> : ''}.</p>
        <Button variant="outline" asChild>
          <Link to="/alerts">Back to Alerts</Link>
        </Button>
      </div>
    )
  }

  return <ProcessedAlertDetail data={data} similarAlerts={similarAlerts} />
}
