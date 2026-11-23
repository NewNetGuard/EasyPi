import { Bot, Loader2 } from 'lucide-react';
import type { Ref, RefObject } from 'react';
import type { ChatMessage } from '../../api/ai';

interface AIAssistantMessagesProps {
  loadingHistory: boolean;
  messages: ChatMessage[];
  messagesEndRef: RefObject<HTMLDivElement | null>;
}

export function AIAssistantMessages({
  loadingHistory,
  messages,
  messagesEndRef,
}: AIAssistantMessagesProps) {
  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-4xl mx-auto px-6 py-6">
        {loadingHistory ? (
          <div className="flex flex-col items-center justify-center h-full min-h-[300px]">
            <Loader2 className="w-8 h-8 animate-spin mb-3" style={{ color: '#8b5cf6' }} />
            <p style={{ color: 'var(--ai-text-muted)' }}>Loading chat history...</p>
          </div>
        ) : messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full min-h-[300px] text-center">
            <div className="p-4 rounded-2xl mb-4" style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
              <Bot className="w-12 h-12" style={{ color: '#ffffff' }} />
            </div>
            <h2 className="text-base font-semibold mb-2" style={{ color: 'var(--ai-text)' }}>Start a Conversation</h2>
            <p style={{ color: 'var(--ai-text-muted)' }}>
              Ask about EasyPi features, setup, administration, or service configuration
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {messages.map((message, index) => (
              <div key={index} className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div
                  className="max-w-[75%] rounded-2xl px-4 py-3"
                  style={message.role === 'user'
                    ? { background: 'linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)', color: '#ffffff' }
                    : { background: 'var(--ai-surface)', color: 'var(--ai-text)', border: '1px solid var(--ai-border)' }
                  }
                >
                  <p className="whitespace-pre-wrap break-words">
                    {message.content || (
                      <span className="flex items-center gap-2" style={{ color: 'var(--ai-text-subtle)' }}>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Thinking...
                      </span>
                    )}
                  </p>
                  {message.timestamp && (
                    <p className="text-xs mt-2" style={{ color: message.role === 'user' ? 'rgba(255,255,255,0.6)' : 'var(--ai-text-subtle)' }}>
                      {new Date(message.timestamp).toLocaleTimeString()}
                    </p>
                  )}
                </div>
              </div>
            ))}
            <div ref={messagesEndRef as Ref<HTMLDivElement>} />
          </div>
        )}
      </div>
    </div>
  );
}
