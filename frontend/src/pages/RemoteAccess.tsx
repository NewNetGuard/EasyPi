/**
 * Remote Access Page
 * 
 * Simple ON/OFF control for remote VPN access.
 * All complexity is hidden - user just enables/disables.
 */

import { TailscaleRemoteAccess } from '../components/RemoteAccess'

export default function RemoteAccess() {
  return (
    <div>
      <div className="max-w-4xl mx-auto">
        <TailscaleRemoteAccess />
      </div>
    </div>
  )
}
