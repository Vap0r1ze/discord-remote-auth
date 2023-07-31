import { KeyPairSyncResult } from 'crypto'
import { EventEmitter } from 'eventemitter3'

interface EventTypes {
    pendingRemoteInit: [fingerprint: string]
    pendingFinish: [user: {
        id: string,
        discriminator: string,
        avatar: string | null,
        username: string,
    }]
    finish: [token: string]
    cancel: []
    close: []
    raw: [packet: any]
}

export class RemoteAuthClient extends EventEmitter<EventTypes> {
    constructor (options?: { debug: boolean })

    debug: boolean
    intervals: number[]
    keyPair: KeyPairSyncResult<string, string>
    canceled: boolean

    connect(): void
}
