import { useCallback, useEffect, useRef, useState } from 'react';
import type { Dispatch, KeyboardEvent, MouseEvent, RefObject, SetStateAction } from 'react';
import toast from 'react-hot-toast';
import { aiApi, type ChatMessage, type ChatSession } from '../../api/ai';
import { buildSessionId, sanitizeModelName, sessionStorageKey } from './aiAssistantUtils';

interface UseAIAssistantSessionsParams {
  selectedModel: string;
  setSelectedModel: Dispatch<SetStateAction<string>>;
  temperatureValue: number;
  systemPrompt: string;
  isInstalled: boolean;
  abortActiveStream: () => void;
  onSwitchToChat: () => void;
}

interface UseAIAssistantSessionsResult {
  messages: ChatMessage[];
  setMessages: Dispatch<SetStateAction<ChatMessage[]>>;
  sessionId: string;
  showSessions: boolean;
  setShowSessions: Dispatch<SetStateAction<boolean>>;
  sessions: ChatSession[];
  setSessions: Dispatch<SetStateAction<ChatSession[]>>;
  loadingHistory: boolean;
  messagesEndRef: RefObject<HTMLDivElement | null>;
  handleNewChat: () => void;
  handleSwitchSession: (targetSession: ChatSession) => Promise<void>;
  handleClearChat: () => Promise<void>;
  handleDeleteSession: (targetSessionId: string, event: MouseEvent) => Promise<void>;
  handleKeyPress: (event: KeyboardEvent, onSubmit: () => void) => void;
}

export function useAIAssistantSessions({
  selectedModel,
  setSelectedModel,
  temperatureValue,
  systemPrompt,
  isInstalled,
  abortActiveStream,
  onSwitchToChat,
}: UseAIAssistantSessionsParams): UseAIAssistantSessionsResult {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [sessionId, setSessionId] = useState<string>(() => {
    const saved = localStorage.getItem(sessionStorageKey(selectedModel));
    return saved || buildSessionId(selectedModel);
  });
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [showSessions, setShowSessions] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    localStorage.setItem('ai_last_model', selectedModel);

    const storedSession = localStorage.getItem(sessionStorageKey(selectedModel));
    const expectedPrefix = `session_${sanitizeModelName(selectedModel)}_`;
    const hasValidStoredSession = Boolean(storedSession && storedSession.startsWith(expectedPrefix));
    const nextSessionId = hasValidStoredSession ? storedSession! : buildSessionId(selectedModel);

    if (!hasValidStoredSession) {
      localStorage.setItem(sessionStorageKey(selectedModel), nextSessionId);
    }

    if (nextSessionId !== sessionId) {
      setSessionId(nextSessionId);
      setMessages([]);
    }
  }, [selectedModel, sessionId]);

  useEffect(() => {
    const expectedPrefix = `session_${sanitizeModelName(selectedModel)}_`;
    const isSessionForModel = Boolean(sessionId && sessionId.startsWith(expectedPrefix));

    const loadHistory = async () => {
      if (!sessionId || !isInstalled || !isSessionForModel) {
        return;
      }

      setLoadingHistory(true);
      try {
        const history = await aiApi.getHistory(sessionId);
        if (history && history.length > 0) {
          setMessages(history.map((message) => ({
            role: message.role,
            content: message.content,
            timestamp: message.timestamp || new Date().toISOString(),
          })));
          return;
        }

        setMessages([]);
      } catch (err) {
        console.error('Failed to load chat history:', err);
      } finally {
        setLoadingHistory(false);
      }
    };

    void loadHistory();

    if (isSessionForModel) {
      localStorage.setItem(sessionStorageKey(selectedModel), sessionId);
    }
  }, [isInstalled, selectedModel, sessionId]);

  useEffect(() => {
    const loadSessions = async () => {
      if (!isInstalled) {
        setSessions([]);
        return;
      }

      try {
        const data = await aiApi.getSessions();
        const currentSession = localStorage.getItem(sessionStorageKey(selectedModel)) || sessionId;
        const filtered = data.filter((session) => {
          if (session.model) {
            return session.model === selectedModel;
          }

          return session.session_id === currentSession;
        });
        setSessions(filtered);
      } catch (err) {
        console.error('Failed to load sessions:', err);
      }
    };

    void loadSessions();
  }, [isInstalled, messages.length, selectedModel, sessionId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleNewChat = useCallback(() => {
    abortActiveStream();
    const nextSessionId = buildSessionId(selectedModel);
    setSessionId(nextSessionId);
    setMessages([]);
    setShowSessions(false);
    localStorage.setItem(sessionStorageKey(selectedModel), nextSessionId);
    toast.success('New chat started');
  }, [abortActiveStream, selectedModel]);

  const handleSwitchSession = useCallback(async (targetSession: ChatSession) => {
    if (targetSession.session_id === sessionId) {
      setShowSessions(false);
      return;
    }

    abortActiveStream();
    const targetModel = targetSession.model || selectedModel;
    let appliedModel = selectedModel;

    if (targetModel && targetModel !== selectedModel) {
      try {
        await aiApi.updateConfig({
          model_name: targetModel,
          temperature: temperatureValue,
          system_prompt: systemPrompt,
        });
        setSelectedModel(targetModel);
        appliedModel = targetModel;
      } catch {
        toast.error('Failed to switch model');
      }
    }

    setSessionId(targetSession.session_id);
    setMessages([]);
    localStorage.setItem(sessionStorageKey(appliedModel), targetSession.session_id);
    localStorage.setItem('ai_last_model', appliedModel);
    onSwitchToChat();
    setShowSessions(false);
  }, [
    abortActiveStream,
    onSwitchToChat,
    selectedModel,
    sessionId,
    setSelectedModel,
    systemPrompt,
    temperatureValue,
  ]);

  const handleClearChat = useCallback(async () => {
    if (!confirm('Clear this chat history?')) {
      return;
    }

    try {
      await aiApi.clearHistory(sessionId);
      setMessages([]);
      toast.success('Chat cleared');
      const data = await aiApi.getSessions();
      setSessions(data);
    } catch {
      toast.error('Failed to clear chat');
    }
  }, [sessionId]);

  const handleDeleteSession = useCallback(async (targetSessionId: string, event: MouseEvent) => {
    event.stopPropagation();
    if (!confirm('Delete this chat?')) {
      return;
    }

    try {
      await aiApi.clearHistory(targetSessionId);
      const data = await aiApi.getSessions();
      setSessions(data);

      if (targetSessionId === sessionId) {
        handleNewChat();
      }

      toast.success('Chat deleted');
    } catch {
      toast.error('Failed to delete chat');
    }
  }, [handleNewChat, sessionId]);

  const handleKeyPress = useCallback((event: KeyboardEvent, onSubmit: () => void) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      onSubmit();
    }
  }, []);

  return {
    messages,
    setMessages,
    sessionId,
    showSessions,
    setShowSessions,
    sessions,
    setSessions,
    loadingHistory,
    messagesEndRef,
    handleNewChat,
    handleSwitchSession,
    handleClearChat,
    handleDeleteSession,
    handleKeyPress,
  };
}
