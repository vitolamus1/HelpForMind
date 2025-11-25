import styles from '../styles/AlertBox.module.css';

export type AlertType = {
  type: 'warning' | 'error' | 'success' | 'info';
  message: string;
  onConfirm?: () => void;
  onCancel?: () => void;
};

interface AlertBoxProps {
  alert: AlertType;
}

export default function AlertBox({ alert }: AlertBoxProps) {
  return (
    <div className={styles.alertOverlay} onClick={() => alert.onCancel?.()}>
      <div className={`${styles.alertBox} ${styles[alert.type]}`} onClick={e => e.stopPropagation()}>
        <div className={styles.alertIcon}>
          {alert.type === 'warning' && '⚠️'}
          {alert.type === 'error' && '❌'}
          {alert.type === 'success' && '✅'}
          {alert.type === 'info' && 'ℹ️'}
        </div>
        <h2 className={styles.alertTitle}>
          {alert.type === 'warning' && 'Warning'}
          {alert.type === 'error' && 'Error'}
          {alert.type === 'success' && 'Success'}
          {alert.type === 'info' && 'Information'}
        </h2>
        <p className={styles.alertMessage}>{alert.message}</p>
        <div className={styles.alertButtons}>
          {alert.onCancel && (
            <button className={styles.alertCancel} onClick={alert.onCancel}>
              Cancel
            </button>
          )}
          <button className={styles.alertConfirm} onClick={alert.onConfirm}>
            {alert.onCancel ? 'Continue' : 'OK'}
          </button>
        </div>
      </div>
    </div>
  );
}
