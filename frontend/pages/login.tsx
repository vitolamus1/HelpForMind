import { useState } from 'react';
import { useRouter } from 'next/router';
import styles from '../styles/login.module.css';
import { api } from '../lib/api';
import AlertBox, { AlertType } from '../components/AlertBox';

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<'login'|'register'>('login');
  const [nickname, setNickname] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [anonNickname, setAnonNickname] = useState('');
  const [alertBox, setAlertBox] = useState<AlertType | null>(null);
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [requires2FA, setRequires2FA] = useState(false);

  async function anon(e: React.FormEvent) {
    e.preventDefault();
    
    setAlertBox({
      type: 'warning',
      message: '⚠️ WAŻNE OSTRZEŻENIE:\n\n• NIE BĘDZIESZ MÓGŁ zalogować się ponownie po wylogowaniu\n• Nie możemy się z Tobą skontaktować ani odzyskać Twoich danych\n• Wszystkie Twoje dane zostaną trwale utracone po wylogowaniu\n\nRozważ utworzenie zwykłego konta dla bezpieczeństwa danych.',
      onConfirm: async () => {
        setAlertBox(null);
        try {
          const { data } = await api.post('/auth/anonymous', { nickname: anonNickname });
          localStorage.setItem('token', data.token);
          localStorage.setItem('nickname', anonNickname);
          router.push('/');
        } catch (err: any) {
          console.error('Anonymous registration failed:', err);
          setAlertBox({
            type: 'error',
            message: 'Błąd: ' + (err.response?.data?.error || err.message || 'Nie można połączyć z serwerem'),
            onConfirm: () => setAlertBox(null)
          });
        }
      },
      onCancel: () => setAlertBox(null)
    });
  }

  async function login(e: React.FormEvent) {
    e.preventDefault();
    try {
      const loginData: any = { nickname, password };
      if (requires2FA) {
        loginData.twoFactorCode = twoFactorCode;
      }
      
      const { data } = await api.post('/auth/login', loginData);
      
      if (data.requires2FA) {
        setRequires2FA(true);
        setAlertBox({
          type: 'info',
          message: 'Wprowadź kod z aplikacji Authy',
          onConfirm: () => setAlertBox(null)
        });
        return;
      }
      
      const storage = rememberMe ? localStorage : sessionStorage;
      storage.setItem('token', data.token);
      storage.setItem('nickname', data.user?.nickname || nickname);
      router.push('/');
    } catch (err: any) {
      console.error('Login failed:', err);
      setAlertBox({
        type: 'error',
        message: 'Błąd logowania: ' + (err.response?.data?.error || err.message || 'Nie można połączyć z serwerem'),
        onConfirm: () => setAlertBox(null)
      });
    }
  }

  async function register(e: React.FormEvent) {
    e.preventDefault();
    try {
      const { data } = await api.post('/auth/register', { nickname, password });
      localStorage.setItem('token', data.token);
      localStorage.setItem('nickname', nickname);
      router.push('/');
    } catch (err: any) {
      console.error('Registration failed:', err);
      setAlertBox({
        type: 'error',
        message: 'Błąd rejestracji: ' + (err.response?.data?.error || err.message || 'Nie można połączyć z serwerem'),
        onConfirm: () => setAlertBox(null)
      });
    }
  }

  return (
    <main className={styles.screen}>
      <h1 className={styles.brand}>🧠 HelpForMind</h1>
      <button 
        onClick={() => router.push('/main')}
        style={{
          position: 'absolute',
          top: '20px',
          left: '20px',
          padding: '12px 24px',
          borderRadius: '12px',
          border: 'none',
          background: 'rgba(255,255,255,0.15)',
          color: '#fff',
          fontSize: '16px',
          fontWeight: '600',
          cursor: 'pointer',
          transition: 'all 0.3s',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.2)',
          zIndex: 10,
          backdropFilter: 'blur(10px)'
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = 'scale(1.05)';
          e.currentTarget.style.background = 'rgba(255,255,255,0.25)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = 'scale(1)';
          e.currentTarget.style.background = 'rgba(255,255,255,0.15)';
        }}
      >
        🏠 Strona główna
      </button>
      <div className={styles.card}>
        <h1 className={styles.title}>{mode === 'login' ? 'Logowanie' : 'Rejestracja'}</h1>
        <br/>

        {mode === 'login' ? (
          <form onSubmit={login} className={styles.form}>
            <div className={styles.inputGroup}>
              <span className={styles.inputIcon}>👤</span>
              <input 
                className={styles.input} 
                placeholder="Nazwa użytkownika" 
                type="text"
                value={nickname} 
                onChange={e=>setNickname(e.target.value)} 
                required 
              />
            </div>

            <div className={styles.inputGroup}>
              <span className={styles.inputIcon}>🔒</span>
              <input 
                className={styles.input} 
                placeholder="Hasło" 
                type="password"
                value={password} 
                onChange={e=>setPassword(e.target.value)} 
                required 
              />
            </div>

            {requires2FA && (
              <div className={styles.inputGroup}>
                <span className={styles.inputIcon}>🔐</span>
                <input 
                  className={styles.input} 
                  placeholder="Kod 2FA (6 cyfr)" 
                  type="text"
                  maxLength={6}
                  value={twoFactorCode} 
                  onChange={e=>setTwoFactorCode(e.target.value.replace(/\D/g, ''))} 
                  required 
                  style={{letterSpacing: '4px', textAlign: 'center', fontFamily: 'monospace'}}
                />
              </div>
            )}

            <div className={styles.options}>
              <label className={styles.remember}>
                <input 
                  type="checkbox" 
                  checked={rememberMe} 
                  onChange={e=>setRememberMe(e.target.checked)}
                />
                <span>Zapamiętaj mnie</span>
              </label>
              <a href="#" className={styles.forgot}>Zapomniałeś hasła?</a>
            </div>

            <button className={styles.submitButton} type="submit">Zaloguj się</button>

            <p className={styles.switchMode}>
              Nie masz konta? <button type="button" onClick={()=>setMode('register')} className={styles.switchLink}>Zarejestruj się</button>
            </p>
          </form>
        ) : (
          <form onSubmit={register} className={styles.form}>
            <div className={styles.inputGroup}>
              <span className={styles.inputIcon}>👤</span>
              <input 
                className={styles.input} 
                placeholder="Nazwa użytkownika" 
                value={nickname} 
                onChange={e=>setNickname(e.target.value)} 
                required 
              />
            </div>

            <div className={styles.inputGroup}>
              <span className={styles.inputIcon}>🔒</span>
              <input 
                className={styles.input} 
                placeholder="Hasło" 
                type="password"
                value={password} 
                onChange={e=>setPassword(e.target.value)} 
                required 
              />
            </div>

            <button className={styles.submitButton} type="submit">Zarejestruj się</button>

            <p className={styles.switchMode}>
              Masz już konto? <button type="button" onClick={()=>setMode('login')} className={styles.switchLink}>Zaloguj się</button>
            </p>
          </form>
        )}

        <div className={styles.divider}>
          <span>LUB</span>
        </div>

        <form onSubmit={anon} className={styles.anonForm}>
          <p className={styles.anonTitle}>Utwórz anonimowe konto</p>
          <div className={styles.inputGroup}>
            <span className={styles.inputIcon}>🎭</span>
            <input 
              className={styles.input} 
              placeholder="Wybierz pseudonim" 
              value={anonNickname} 
              onChange={e=>setAnonNickname(e.target.value)} 
              required 
            />
          </div>
          <button className={styles.anonButton} type="submit">Kontynuuj anonimowo</button>
        </form>
      </div>

      {alertBox && <AlertBox alert={alertBox} />}
    </main>
  );
}
