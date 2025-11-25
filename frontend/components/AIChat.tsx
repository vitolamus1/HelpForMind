import { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import styles from '../styles/AIChat.module.css';
import AlertBox, { AlertType } from './AlertBox';

// Use Next.js API proxy to avoid CORS/mixed-content issues
const API_BASE = '/api';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  createdAt: string;
}

interface AIChatProps {
  token: string;
  isOpen: boolean;
  onClose: () => void;
  inline?: boolean; // render as inline block instead of overlay
}

export default function AIChat({ token, isOpen, onClose, inline = false }: AIChatProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [alertBox, setAlertBox] = useState<AlertType | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    if (isOpen && messages.length === 0) {
      loadHistory();
    }
  }, [isOpen]);

  const loadHistory = async () => {
    setIsLoadingHistory(true);
    try {
      const response = await axios.get(`${API_BASE}/ai-chat/history`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setMessages(response.data);
    } catch (error) {
      console.error('Error loading chat history:', error);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  const sendMessage = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage = input.trim();
    setInput('');
    
    // Add user message optimistically
    const tempUserMessage: Message = {
      id: `temp-${Date.now()}`,
      role: 'user',
      content: userMessage,
      createdAt: new Date().toISOString(),
    };
    setMessages(prev => [...prev, tempUserMessage]);
    setIsLoading(true);

    try {
      const response = await axios.post(
        `${API_BASE}/ai-chat`,
        { message: userMessage },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      const aiMessage: Message = {
        id: `ai-${Date.now()}`,
        role: 'assistant',
        content: response.data.message,
        createdAt: response.data.timestamp,
      };

      setMessages(prev => [...prev, aiMessage]);
    } catch (error: any) {
      console.error('Error sending message:', error);
      
      // Check if error is related to invalid API key or quota
      const isAPIKeyError = error.response?.status === 401 || 
                            error.response?.status === 403 || 
                            error.response?.data?.error?.includes('API') ||
                            error.response?.data?.error?.includes('key') ||
                            error.response?.data?.error?.includes('quota');
      
      setMessages(prev => [
        ...prev,
        {
          id: `error-${Date.now()}`,
          role: 'assistant',
          content: isAPIKeyError 
            ? 'W tym miejscu powinien być asystent AI, ale w darmowym planie jest ograniczona ilość wiadomości, które można wysłać, ale aby AI działało, wystarczy wkleić swój kod z Google Gemini API.'
            : 'Przepraszam, wystąpił błąd. Spróbuj ponownie później.',
          createdAt: new Date().toISOString(),
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const clearHistory = async () => {
    setAlertBox({
      type: 'warning',
      message: 'Czy na pewno chcesz usunąć całą historię rozmów?',
      onConfirm: async () => {
        setAlertBox(null);
        try {
          await axios.delete(`${API_BASE}/ai-chat/history`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          setMessages([]);
        } catch (error) {
          console.error('Error clearing history:', error);
          setAlertBox({
            type: 'error',
            message: 'Nie udało się wyczyścić historii',
            onConfirm: () => setAlertBox(null)
          });
        }
      },
      onCancel: () => setAlertBox(null)
    });
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  if (!isOpen) return null;

  // If rendered inline, don't use overlay wrapper
  if (inline) {
    return (
      <div className={styles.inlineWrapper}>
        <div className={styles.inlineChatContainer}>
          <div className={styles.header}>
            <div className={styles.headerContent}>
              <h3 className={styles.title}>&#x1F916; Empatyczny Moderator AI</h3>
              <p className={styles.subtitle}>Bezpieczne miejsce do rozmowy z asystentem AI</p>
            </div>
            <div className={styles.headerButtons}>
              <button 
                onClick={clearHistory} 
                className={styles.clearButton}
                title="Wyczyść historię"
              >
                🗑️
              </button>
              <button onClick={onClose} className={styles.closeButton}>
                ✕
              </button>
            </div>
          </div>

          <div className={styles.messagesContainer}>
            {isLoadingHistory ? (
              <div className={styles.loading}>Ładowanie historii...</div>
            ) : messages.length === 0 ? (
              <div className={styles.emptyState}>
                <p className={styles.emptyIcon}>💬</p>
                <p className={styles.emptyText}>
                  Witaj! Jestem tu, aby Cię wysłuchać.
                </p>
                <p className={styles.emptySubtext}>
                  Możesz mi napisać o swoim dniu, uczuciach, przemyśleniach...
                  <br />
                  To bezpieczna przestrzeń tylko dla Ciebie.
                </p>
              </div>
            ) : (
              messages.map((msg) => (
                <div
                  key={msg.id}
                  className={`${styles.message} ${
                    msg.role === 'user' ? styles.userMessage : styles.aiMessage
                  }`}
                >
                  <div className={styles.messageContent}>
                    <div className={styles.messageText}>{msg.content}</div>
                    <div className={styles.messageTime}>
                      {new Date(msg.createdAt).toLocaleTimeString('pl-PL', {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </div>
                  </div>
                </div>
              ))
            )}
            {isLoading && (
              <div className={`${styles.message} ${styles.aiMessage}`}>
                <div className={styles.messageContent}>
                  <div className={styles.typing}>
                    <span></span>
                    <span></span>
                    <span></span>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          <div className={styles.inputContainer}>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Napisz o swoim dniu, uczuciach..."
              className={styles.input}
              disabled={isLoading}
              rows={3}
            />
            <button
              onClick={sendMessage}
              disabled={!input.trim() || isLoading}
              className={styles.sendButton}
            >
              {isLoading ? 'Wysyłam...' : 'Wyślij'}
            </button>
          </div>

          {alertBox && <AlertBox alert={alertBox} />}
        </div>
      </div>
    );
  }

  return (
    <div className={styles.overlay}>
      <div className={styles.chatContainer}>
        <div className={styles.header}>
          <div className={styles.headerContent}>
            <h3 className={styles.title}>&#x1F916; Empatyczny Moderator AI</h3>
            <p className={styles.subtitle}>Bezpieczne miejsce do rozmowy z asystentem AI</p>
          </div>
          <div className={styles.headerButtons}>
            <button 
              onClick={clearHistory} 
              className={styles.clearButton}
              title="Wyczyść historię"
            >
              🗑️
            </button>
            <button onClick={onClose} className={styles.closeButton}>
              ✕
            </button>
          </div>
        </div>

        <div className={styles.messagesContainer}>
          {isLoadingHistory ? (
            <div className={styles.loading}>Ładowanie historii...</div>
          ) : messages.length === 0 ? (
            <div className={styles.emptyState}>
              <p className={styles.emptyIcon}>💬</p>
              <p className={styles.emptyText}>
                Witaj! Jestem tu, aby Cię wysłuchać.
              </p>
              <p className={styles.emptySubtext}>
                Możesz mi napisać o swoim dniu, uczuciach, przemyśleniach...
                <br />
                To bezpieczna przestrzeń tylko dla Ciebie.
              </p>
            </div>
          ) : (
            messages.map((msg) => (
              <div
                key={msg.id}
                className={`${styles.message} ${
                  msg.role === 'user' ? styles.userMessage : styles.aiMessage
                }`}
              >
                <div className={styles.messageContent}>
                  <div className={styles.messageText}>{msg.content}</div>
                  <div className={styles.messageTime}>
                    {new Date(msg.createdAt).toLocaleTimeString('pl-PL', {
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </div>
                </div>
              </div>
            ))
          )}
          {isLoading && (
            <div className={`${styles.message} ${styles.aiMessage}`}>
              <div className={styles.messageContent}>
                <div className={styles.typing}>
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        <div className={styles.inputContainer}>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Napisz o swoim dniu, uczuciach..."
            className={styles.input}
            disabled={isLoading}
            rows={3}
          />
          <button
            onClick={sendMessage}
            disabled={!input.trim() || isLoading}
            className={styles.sendButton}
          >
            {isLoading ? 'Wysyłam...' : 'Wyślij'}
          </button>
        </div>

        {/* Alert Box */}
        {alertBox && <AlertBox alert={alertBox} />}
      </div>
    </div>
  );
}
