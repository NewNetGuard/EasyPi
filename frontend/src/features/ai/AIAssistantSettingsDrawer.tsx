import { RotateCcw, Trash2, X } from 'lucide-react';
import type { AIModelInfo } from '../../api/ai';

interface AIAssistantSettingsDrawerProps {
  show: boolean;
  models: AIModelInfo[];
  selectedModel: string;
  temperatureValue: number;
  systemPrompt: string;
  modelPath: string | null;
  savingSettings: boolean;
  isModelInstalled: (modelName: string) => boolean;
  onClose: () => void;
  onModelSelect: (modelName: string) => void;
  onTemperatureChange: (value: number) => void;
  onSystemPromptChange: (value: string) => void;
  onReset: () => void;
  onSave: () => void;
  onDeleteModel: () => void;
  onUninstall: () => void;
}

export function AIAssistantSettingsDrawer({
  show,
  models,
  selectedModel,
  temperatureValue,
  systemPrompt,
  modelPath,
  savingSettings,
  isModelInstalled,
  onClose,
  onModelSelect,
  onTemperatureChange,
  onSystemPromptChange,
  onReset,
  onSave,
  onDeleteModel,
  onUninstall,
}: AIAssistantSettingsDrawerProps) {
  if (!show) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      <div className="absolute inset-0" style={{ background: 'rgba(0,0,0,0.5)' }} onClick={onClose} />
      <div className="absolute right-0 top-0 h-full w-full max-w-md shadow-2xl dark:shadow-none" style={{ background: 'var(--ai-surface)' }}>
        <div className="flex flex-col h-full">
          <div className="flex items-center justify-between p-6" style={{ borderBottom: '1px solid var(--ai-border)' }}>
            <h2 className="text-sm font-semibold" style={{ color: 'var(--ai-text)' }}>Settings</h2>
            <button onClick={onClose} className="p-2 rounded-lg" style={{ color: 'var(--ai-text-muted)' }}>
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-6 space-y-6">
            <div>
              <label className="block text-sm font-semibold mb-2" style={{ color: 'var(--ai-text)' }}>Model</label>
              <div className="space-y-2">
                {models.map((model) => {
                  const installed = isModelInstalled(model.name);
                  const isSelected = selectedModel === model.name;

                  return (
                    <div
                      key={model.name}
                      onClick={() => onModelSelect(model.name)}
                      className={`rounded-lg p-3 cursor-pointer transition-all border-2 ${isSelected
                        ? (installed ? 'border-emerald-500 bg-emerald-50 dark:bg-dark-900' : 'border-violet-500 bg-violet-50 dark:bg-dark-900')
                        : 'border-gray-200 dark:border-dark-700 bg-gray-50 dark:bg-dark-900'
                        }`}
                    >
                      <div className="flex items-center gap-2">
                        <div
                          className="w-4 h-4 rounded-full border-2 flex items-center justify-center flex-shrink-0"
                          style={{
                            borderColor: isSelected ? (installed ? '#10b981' : '#8b5cf6') : '#d1d5db',
                            background: isSelected ? (installed ? '#10b981' : '#8b5cf6') : 'transparent'
                          }}
                        >
                          {isSelected && <div className="w-1.5 h-1.5 rounded-full bg-white" />}
                        </div>
                        <span className="font-medium text-sm" style={{ color: 'var(--ai-text)' }}>
                          {model.display_name}
                        </span>
                        <span className="text-xs" style={{ color: 'var(--ai-text-subtle)' }}>
                          {model.size_gb.toFixed(1)} GB
                        </span>
                        {installed && (
                          <span className="ml-auto px-1.5 py-0.5 text-xs rounded bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400">
                            ✓
                          </span>
                        )}
                      </div>
                      {isSelected && !installed && (
                        <p className="text-xs mt-1 ml-6 text-yellow-700 dark:text-yellow-400">
                          Warning: Not installed
                        </p>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-2">
                <label className="text-sm font-semibold" style={{ color: 'var(--ai-text)' }}>Temperature</label>
                <span className="text-sm font-bold" style={{ color: '#8b5cf6' }}>{temperatureValue.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min={0}
                max={1.5}
                step={0.05}
                value={temperatureValue}
                onChange={(event) => onTemperatureChange(Number(event.target.value))}
                className="w-full"
              />
            </div>

            <div>
              <label className="block text-sm font-semibold mb-2" style={{ color: 'var(--ai-text)' }}>System Prompt</label>
              <textarea
                value={systemPrompt}
                onChange={(event) => onSystemPromptChange(event.target.value)}
                rows={4}
                className="w-full rounded-xl px-4 py-3 resize-none"
                style={{ background: 'var(--ai-surface-2)', border: '2px solid var(--ai-border)', color: 'var(--ai-text)' }}
              />
            </div>

            <div className="pt-6 space-y-3" style={{ borderTop: '1px solid var(--ai-border)' }}>
              {modelPath && (
                <div className="rounded-xl p-3" style={{ background: 'var(--ai-surface-2)' }}>
                  <p className="text-xs font-semibold mb-1" style={{ color: 'var(--ai-text-muted)' }}>Model path:</p>
                  <p className="text-xs font-mono break-all" style={{ color: 'var(--ai-text)' }}>{modelPath}</p>
                </div>
              )}

              <button
                onClick={onDeleteModel}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-yellow-50 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-400 border border-yellow-300 dark:border-yellow-700"
              >
                <Trash2 className="w-4 h-4" />
                Delete model only
              </button>

              <button
                onClick={onUninstall}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400"
              >
                <Trash2 className="w-4 h-4" />
                Uninstall Ollama completely
              </button>
            </div>
          </div>

          <div className="p-6 space-y-3" style={{ borderTop: '1px solid var(--ai-border)' }}>
            <button
              onClick={onReset}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-xl"
              style={{ border: '2px solid var(--ai-border)', color: 'var(--ai-text)' }}
            >
              <RotateCcw className="w-4 h-4" />
              Reset
            </button>
            <button
              onClick={onSave}
              disabled={savingSettings}
              className="w-full font-semibold py-3 rounded-xl disabled:opacity-50"
              style={{ background: 'linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)', color: '#ffffff' }}
            >
              {savingSettings ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
