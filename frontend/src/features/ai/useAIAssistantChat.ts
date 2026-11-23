import { useCallback, useState } from 'react';
import toast from 'react-hot-toast';
import { aiApi, type ChatMessage } from '../../api/ai';

interface UseAIAssistantChatParams {
  selectedModel: string;
  temperatureValue: number;
  installedModels: string[];
  isModelInstalled: (modelName: string) => boolean;
  sessionId: string;
  setMessages: React.Dispatch<React.SetStateAction<ChatMessage[]>>;
  setError: (value: string | null) => void;
  abortActiveStream: () => void;
  setStreamController: (controller: AbortController | null) => void;
  onRequireModelInstall: () => void;
}

interface UseAIAssistantChatResult {
  input: string;
  setInput: React.Dispatch<React.SetStateAction<string>>;
  loading: boolean;
  sendMessage: (messageText?: string) => Promise<void>;
}

export function useAIAssistantChat({
  selectedModel,
  temperatureValue,
  installedModels,
  isModelInstalled,
  sessionId,
  setMessages,
  setError,
  abortActiveStream,
  setStreamController,
  onRequireModelInstall,
}: UseAIAssistantChatParams): UseAIAssistantChatResult {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const sendMessage = useCallback(async (messageText?: string) => {
    const text = messageText || input;
    if (!text.trim() || loading) {
      return;
    }

    const hasModels = installedModels.length > 0;
    const selectedInstalled = isModelInstalled(selectedModel);
    if (!hasModels || !selectedInstalled) {
      const message = !hasModels
        ? 'No AI models installed. Install a model first.'
        : 'Selected model is not installed. Choose an installed model or install it.';
      setError(message);
      toast.error(message);
      onRequireModelInstall();
      return;
    }

    abortActiveStream();

    const userMessage: ChatMessage = {
      role: 'user',
      content: text,
      timestamp: new Date().toISOString(),
    };

    setInput('');
    setLoading(true);
    setError(null);

    setMessages((prev) => [
      ...prev,
      userMessage,
      { role: 'assistant', content: '', timestamp: new Date().toISOString() },
    ]);

    const controller = new AbortController();
    setStreamController(controller);

    try {
      await aiApi.streamMessage(
        { message: text, session_id: sessionId, temperature: temperatureValue },
        (chunk) => {
          setMessages((prev) => {
            const updated = [...prev];
            const lastIndex = updated.length - 1;
            if (lastIndex >= 0 && updated[lastIndex].role === 'assistant') {
              updated[lastIndex] = {
                ...updated[lastIndex],
                content: updated[lastIndex].content + chunk,
              };
            }
            return updated;
          });
        },
        () => {
          setStreamController(null);
          setLoading(false);
        },
        (err) => {
          setStreamController(null);
          setError(err);
          setLoading(false);
          toast.error(`Send error: ${err}`);
        },
        controller.signal,
      );
    } catch (err) {
      setStreamController(null);
      setError(err instanceof Error ? err.message : 'Send error');
      setLoading(false);
    }
  }, [
    abortActiveStream,
    input,
    installedModels.length,
    isModelInstalled,
    loading,
    onRequireModelInstall,
    selectedModel,
    sessionId,
    setStreamController,
    setError,
    setMessages,
    temperatureValue,
  ]);

  return {
    input,
    setInput,
    loading,
    sendMessage,
  };
}
