import { useEffect, useRef, useState } from 'react'
import { Terminal as XTerm } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import { WebLinksAddon } from 'xterm-addon-web-links'
import { getWsUrl } from '../../utils/wsBase'
import { getApiV1BaseUrl } from '../../utils/apiBase'
import { getCsrfHeaders } from '../../utils/csrf'
import 'xterm/css/xterm.css'

type ConnectionStatus = 'connecting' | 'connected' | 'error' | 'closed'

const TerminalEmulator = () => {
    const terminalRef = useRef<HTMLDivElement>(null)
    const xtermRef = useRef<XTerm | null>(null)
    const fitAddonRef = useRef<FitAddon | null>(null)
    const wsRef = useRef<WebSocket | null>(null)
    const terminalReadyRef = useRef(false)
    
    const [status, setStatus] = useState<ConnectionStatus>('connecting')
    const [errorMessage, setErrorMessage] = useState<string>('')
    const [errorDetail, setErrorDetail] = useState<string>('')
    const connectionInitialized = useRef(false)

    useEffect(() => {
        // Prevent double mounting in React StrictMode
        if (!terminalRef.current || connectionInitialized.current) return
        connectionInitialized.current = true

        // Get WebSocket token using httpOnly cookies
        const initWebSocket = async () => {
            try {
                const csrfHeaders = await getCsrfHeaders(getApiV1BaseUrl())

                // Get temporary WS token via authenticated request
                const response = await fetch(`${getApiV1BaseUrl()}/auth/terminal-ws-token`, {
                    method: 'POST',
                    credentials: 'include',  // Send httpOnly cookies
                    headers: Object.keys(csrfHeaders).length ? csrfHeaders : undefined,
                })
                
                if (!response.ok) {
                    // Handle specific statuses for clearer messages
                    if (response.status === 401) {
                        setStatus('error')
                        setErrorMessage('Not authenticated. Please log in.')
                        setErrorDetail('Not authenticated (401)')
                        return
                    }
                    if (response.status === 429) {
                        const retryAfter = response.headers.get('Retry-After')
                        const waitMsg = retryAfter ? `Too many requests. Retry after ${retryAfter}s` : 'Too many requests. Please wait and try again.'
                        setStatus('error')
                        setErrorMessage('Rate limited')
                        setErrorDetail(waitMsg)
                        return
                    }

                    // Try to parse error details from the response body
                    let errText = 'Failed to get WebSocket token'
                    try {
                        const errBody = await response.json()
                        if (errBody && errBody.detail) errText = errBody.detail
                    } catch (_) {}

                    setStatus('error')
                    setErrorMessage(errText)
                    setErrorDetail(`Status ${response.status}`)
                    return
                }
                
                const data = await response.json()
                const wsToken = data.ws_token
                
                if (!wsToken) {
                    setStatus('error')
                    setErrorMessage('No WebSocket token received')
                    setErrorDetail('Missing ws_token in response')
                    return
                }

                const wsUrl = getWsUrl('/ws/terminal')
                const ws = new WebSocket(wsUrl, [`easypi-terminal.${wsToken}`])
                wsRef.current = ws

                let resizeHandler: (() => void) | null = null

                ws.onopen = () => {
                    setStatus('connected')
                    setErrorMessage('')
                    setErrorDetail('')

                    const terminal = new XTerm({
                        cursorBlink: true,
                        fontSize: 14,
                        fontFamily: 'JetBrains Mono, Courier New, monospace',
                        scrollback: 10000,
                        theme: {
                            background: '#111827',
                            foreground: '#f3f4f6',
                            cursor: '#0ea5e9',
                            selectionBackground: '#374151',
                            black: '#111827',
                            red: '#ef4444',
                            green: '#10b981',
                            yellow: '#f59e0b',
                            blue: '#3b82f6',
                            magenta: '#a855f7',
                            cyan: '#06b6d4',
                            white: '#f3f4f6',
                            brightBlack: '#374151',
                            brightRed: '#f87171',
                            brightGreen: '#34d399',
                            brightYellow: '#fbbf24',
                            brightBlue: '#60a5fa',
                            brightMagenta: '#c084fc',
                            brightCyan: '#22d3ee',
                            brightWhite: '#ffffff'
                        }
                    })

                    const fitAddon = new FitAddon()
                    const webLinksAddon = new WebLinksAddon()
                    terminal.loadAddon(fitAddon)
                    terminal.loadAddon(webLinksAddon)

                    if (terminalRef.current) {
                        terminal.open(terminalRef.current)
                        terminalReadyRef.current = true
                    }

                    xtermRef.current = terminal
                    fitAddonRef.current = fitAddon

                    setTimeout(() => {
                        if (terminalReadyRef.current && fitAddonRef.current) {
                            fitAddonRef.current.fit()
                            terminal.focus()

                            const dims = fitAddonRef.current.proposeDimensions()
                            if (dims && ws.readyState === WebSocket.OPEN) {
                                ws.send(JSON.stringify({
                                    type: 'resize',
                                    cols: dims.cols,
                                    rows: dims.rows
                                }))
                            }

                            // Welcome banner после получения размеров терминала
                            // Очищаем экран от лишнего промпта
                            terminal.write('\x1b[2J\x1b[H')
                            
                            const cyan = '\x1b[1;36m'
                            const green = '\x1b[1;32m'
                            const white = '\x1b[1;37m'
                            const reset = '\x1b[0m'
                            
                            terminal.writeln('')
                            
                            // Простой баннер для мобильных устройств
                            if (window.innerWidth < 640 && dims) {
                                const cols = dims.cols
                                
                                // Центрируем текст "🍓 EasyPi Terminal"
                                const title = '🍓 EasyPi Terminal'
                                const titleLen = 17 // длина текста без эмодзи (эмодзи занимает 2 символа)
                                const titlePadding = Math.max(0, Math.floor((cols - titleLen) / 2))
                                terminal.writeln(' '.repeat(titlePadding) + green + title + reset)
                                
                                terminal.writeln('')
                                
                                // Центрируем текст "✓ Connected to Raspberry Pi" - галочка зелёная, текст белый
                                const subtitle = '✓ Connected to Raspberry Pi'
                                const subtitleLen = 27
                                const subtitlePadding = Math.max(0, Math.floor((cols - subtitleLen) / 2))
                                terminal.writeln(' '.repeat(subtitlePadding) + green + '✓' + white + ' Connected to Raspberry Pi' + reset)
                            } else {
                                // Полный баннер с рамкой для десктопа
                                const bannerWidth = 50
                                const rightCol = bannerWidth + 2
                                const moveToCol = (col: number) => `\x1b[${col}G`

                                const line1 = `            ${green}🍓 EasyPi Terminal${reset}`
                                const line2 = `        ${green}✓${reset} Connected to Raspberry Pi`

                                terminal.writeln(`${cyan}╔${'═'.repeat(bannerWidth)}╗${reset}`)
                                terminal.write(`${cyan}║${reset}${line1}${moveToCol(rightCol)}${cyan}║${reset}\r\n`)
                                terminal.write(`${cyan}║${reset}${line2}${moveToCol(rightCol)}${cyan}║${reset}\r\n`)
                                terminal.writeln(`${cyan}╚${'═'.repeat(bannerWidth)}╝${reset}`)
                            }
                            terminal.writeln('')
                        }
                    }, 100)

                    terminal.onData((data) => {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({
                                type: 'input',
                                data
                            }))
                        }
                    })

                    const handleResize = () => {
                        if (!terminalReadyRef.current || !fitAddonRef.current) {
                            return
                        }

                        fitAddonRef.current.fit()
                        if (ws.readyState === WebSocket.OPEN) {
                            const dims = fitAddonRef.current.proposeDimensions()
                            if (dims) {
                                ws.send(JSON.stringify({
                                    type: 'resize',
                                    cols: dims.cols,
                                    rows: dims.rows
                                }))
                            }
                        }
                    }

                    resizeHandler = handleResize
                    window.addEventListener('resize', handleResize)
                }

                ws.onmessage = (event) => {
                    try {
                        const msg = JSON.parse(event.data)

                        if (msg.type === 'output') {
                            if (terminalReadyRef.current && xtermRef.current) {
                                xtermRef.current.write(msg.data)
                            }
                        } else if (msg.type === 'error') {
                            setStatus('error')
                            if (msg.message === 'AUTH_FAILED') {
                                setErrorMessage('Connection error. Check your admin permissions or authentication.')
                                setErrorDetail('AUTH_FAILED')
                            } else {
                                setErrorMessage('Connection error.')
                                setErrorDetail(msg.message ?? '')
                            }

                            if (terminalReadyRef.current && xtermRef.current) {
                                xtermRef.current.writeln('')
                                xtermRef.current.writeln(`\x1b[1;31m✗\x1b[0m ${msg.message}`)
                            }
                        } else if (msg.type === 'closed') {
                            setStatus('closed')
                            if (terminalReadyRef.current && xtermRef.current) {
                                xtermRef.current.writeln('')
                                xtermRef.current.writeln('\x1b[1;33m⚠\x1b[0m Terminal session ended')
                            }
                            if (ws.readyState === WebSocket.OPEN) {
                                ws.close()
                            }
                        }
                    } catch (error) {
                        console.error('Failed to parse WebSocket message:', error)
                    }
                }

                ws.onerror = () => {
                    setStatus('error')
                    setErrorMessage('Connection error.')
                    setErrorDetail('WebSocket error')
                }

                ws.onclose = (ev) => {
                    // If server closed with policy violation, show auth-related message
                    if (ev && ev.code === 1008) {
                        setStatus('error')
                        setErrorMessage('Connection rejected by server (authorization failure).')
                        setErrorDetail(`Server closed connection (code ${ev.code}): ${ev.reason || 'AUTH_FAILED'}`)
                    } else if (ev && ev.code && ev.code !== 1000 && ev.code !== 1001) {
                        setStatus('error')
                        setErrorMessage('Connection closed unexpectedly.')
                        setErrorDetail(`code ${ev.code} ${ev.reason || ''}`)
                    } else {
                        setStatus((prev) => (prev === 'error' ? 'error' : 'closed'))
                    }

                    if (terminalReadyRef.current && xtermRef.current) {
                        xtermRef.current.writeln('')
                        xtermRef.current.writeln('\x1b[1;33m⚠\x1b[0m Connection closed')
                    }
                }

            } catch (error) {
                console.error('Failed to initialize terminal:', error)
                setStatus('error')
                setErrorMessage('Authentication required')
                setErrorDetail('Please log in to access the terminal')
            }
        }

        initWebSocket()

        return () => {
            // Only cleanup if we're really unmounting, not just StrictMode re-render
            if (!connectionInitialized.current) return
            
            terminalReadyRef.current = false

            if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
                wsRef.current.close()
            }

            if (xtermRef.current) {
                xtermRef.current.dispose()
                xtermRef.current = null
            }

            fitAddonRef.current = null
        }
    }, [])

    return (
        <div className="relative">
            {status === 'connecting' && (
                <div className="absolute inset-0 flex items-center justify-center bg-gray-900 rounded-lg z-10">
                    <div className="text-center px-4">
                        <div className="animate-spin rounded-full h-6 w-6 sm:h-8 sm:w-8 border-b-2 border-blue-500 mx-auto mb-3 sm:mb-4"></div>
                        <p className="text-gray-300 text-sm sm:text-base">Connecting to Raspberry Pi...</p>
                    </div>
                </div>
            )}
            
            {status === 'error' && errorMessage && (
                <div className="absolute inset-0 flex items-center justify-center bg-gray-900 rounded-lg z-10">
                    <div className="text-center p-4 sm:p-6">
                        <div className="text-red-500 text-3xl sm:text-4xl mb-3 sm:mb-4">✗</div>
                        <p className="text-red-400 text-base sm:text-lg font-semibold mb-2">Connection Error</p>
                        <p className="text-gray-300 text-sm sm:text-base">{errorMessage}</p>
                        {errorDetail && (
                            <p className="text-gray-500 text-xs sm:text-sm mt-2 break-words">{errorDetail}</p>
                        )}
                    </div>
                </div>
            )}
            
            <div
                ref={terminalRef}
                className="h-[300px] sm:h-[400px] md:h-[500px] lg:h-[600px] p-2 sm:p-3 md:p-4 bg-gray-900 rounded-lg overflow-auto"
                style={{ overflow: 'auto' }}
                onClick={() => {
                    // Focus terminal on click
                    if (terminalReadyRef.current && xtermRef.current) {
                        xtermRef.current.focus()
                    }
                }}
            />
        </div>
    )
}

export default TerminalEmulator
