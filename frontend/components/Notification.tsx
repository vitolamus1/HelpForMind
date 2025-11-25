import { useEffect } from 'react';
import styles from '../styles/Notification.module.css';

export interface NotificationProps {
  id: string;
  title: string;
  message: string;
  onClose: (id: string) => void;
  onAccept?: (id: string) => void; // Optional accept action
  onDecline?: (id: string) => void; // Optional decline action
  autoClose?: number; // ms, default 5000
}

export default function Notification({ id, title, message, onClose, onAccept, onDecline, autoClose = 5000 }: NotificationProps) {
  console.log('Notification props:', { id, hasAccept: !!onAccept, hasDecline: !!onDecline });
  
  useEffect(() => {
    if (autoClose > 0) {
      const timer = setTimeout(() => {
        onClose(id);
      }, autoClose);
      return () => clearTimeout(timer);
    }
  }, [id, autoClose, onClose]);

  const handleAccept = () => {
    if (onAccept) {
      onAccept(id);
    }
    onClose(id);
  };

  const handleDecline = () => {
    if (onDecline) {
      onDecline(id);
    }
    onClose(id);
  };

  return (
    <div className={styles.notification}>
      <div className={styles.header}>
        <div className={styles.icon}>🔔</div>
        <div className={styles.title}>{title}</div>
        <button 
          className={styles.closeButton} 
          onClick={() => onClose(id)}
          aria-label="Close notification"
        >
          ✕
        </button>
      </div>
      <div className={styles.message}>{message}</div>
      {(onAccept || onDecline) && (
        <div className={styles.actions}>
          {onDecline && (
            <button 
              className={styles.declineButton}
              onClick={handleDecline}
            >
              Odrzuć
            </button>
          )}
          {onAccept && (
            <button 
              className={styles.acceptButton}
              onClick={handleAccept}
            >
              Akceptuj
            </button>
          )}
        </div>
      )}
    </div>
  );
}
