import { useRouter } from 'next/router';
import { useState } from 'react';

export default function Landing2() {
  const router = useRouter();
  const [email, setEmail] = useState('');

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      color: '#ffffff',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif'
    }}>
      <nav style={{
        padding: '20px 32px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottom: '1px solid rgba(255,255,255,0.2)',
        background: 'rgba(0,0,0,0.1)',
        backdropFilter: 'blur(10px)'
      }}>
        <div style={{display: 'flex', alignItems: 'center', gap: 16}}>
          <div style={{fontSize: 32}}>🧠</div>
          <span style={{fontSize: 20, fontWeight: 600}}>HelpForMind</span>
        </div>
        <div style={{display: 'flex', gap: 24, alignItems: 'center'}}>
          <a href="#features" style={{color: '#ffffff', textDecoration: 'none', fontSize: 16, fontWeight: 500}}>Funkcje</a>
          <a href="#about" style={{color: '#ffffff', textDecoration: 'none', fontSize: 16, fontWeight: 500}}>O nas</a>
          <button 
            onClick={() => router.push('/login')}
            style={{
              padding: '10px 20px',
              background: 'rgba(255,255,255,0.2)',
              border: '2px solid rgba(255,255,255,0.3)',
              borderRadius: 12,
              color: '#ffffff',
              fontSize: 14,
              fontWeight: 600,
              cursor: 'pointer',
              backdropFilter: 'blur(10px)',
              transition: 'all 0.3s'
            }}
          >
            Zaloguj się / Załóż konto
          </button>
        </div>
      </nav>


      <section style={{
        maxWidth: 1280,
        margin: '0 auto',
        padding: '128px 32px',
        textAlign: 'center'
      }}>
        <h1 style={{
          fontSize: 64,
          fontWeight: 600,
          lineHeight: 1.2,
          marginBottom: 24,
          color: '#ffffff',
          textShadow: '0 4px 20px rgba(0,0,0,0.3)'
        }}>
          Twój cyfrowy dziennik<br/>zdrowia psychicznego
        </h1>
        <p style={{
          fontSize: 24,
          color: 'rgba(255,255,255,0.9)',
          maxWidth: 800,
          margin: '0 auto 48px',
          lineHeight: 1.5,
          textShadow: '0 2px 10px rgba(0,0,0,0.2)'
        }}>
          HelpForMind pomaga śledzić nastroje, zarządzać emocjami i dbać o zdrowie psychiczne.
          Prywatny, bezpieczny i zawsze dostępny.
        </p>
        <div style={{display: 'flex', gap: 16, justifyContent: 'center', alignItems: 'center'}}>
          <button 
            onClick={() => router.push('/login')}
            style={{
              padding: '16px 48px',
              background: 'rgba(255,255,255,0.95)',
              border: 'none',
              borderRadius: 12,
              color: '#667eea',
              fontSize: 18,
              fontWeight: 700,
              cursor: 'pointer',
              boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
              transition: 'all 0.3s'
            }}
          >
            Zaloguj się / Załóż konto
          </button>
        </div>
      </section>

      <section id="features" style={{
        background: 'rgba(255,255,255,0.1)',
        padding: '96px 32px',
        borderTop: '1px solid rgba(255,255,255,0.2)',
        borderBottom: '1px solid rgba(255,255,255,0.2)',
        backdropFilter: 'blur(10px)'
      }}>
        <div style={{maxWidth: 1280, margin: '0 auto'}}>
          <h2 style={{
            fontSize: 40,
            fontWeight: 600,
            textAlign: 'center',
            marginBottom: 64
          }}>
            Wszystko czego potrzebujesz w jednym miejscu
          </h2>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: 32
          }}>
            {[
              { icon: '📊', title: 'Śledzenie nastrojów', desc: 'Zapisuj swoje nastroje codziennie i obserwuj długoterminowe trendy' },
              { icon: '🤖', title: 'AI Assistant', desc: 'Rozmowa z inteligentnym asystentem, który pomaga zrozumieć emocje' },
              { icon: '📈', title: 'Analityka', desc: 'Zaawansowane wykresy i statystyki Twoich nastrojów' },
              { icon: '🔒', title: 'Prywatność', desc: 'Twoje dane są w pełni zaszyfrowane i bezpieczne' },
              { icon: '💬', title: 'Wsparcie na żywo', desc: 'Chat z moderatorami gdy potrzebujesz natychmiastowej pomocy' },
              { icon: '👥', title: 'Znajomi', desc: 'Dziel się postępami z zaufanymi osobami' }
            ].map((feature, i) => (
              <div key={i} style={{
                padding: 32,
                background: 'rgba(255,255,255,0.15)',
                border: '1px solid rgba(255,255,255,0.2)',
                borderRadius: 16,
                transition: 'all 0.3s',
                backdropFilter: 'blur(10px)',
                boxShadow: '0 4px 16px rgba(0,0,0,0.1)'
              }}>
                <div style={{fontSize: 48, marginBottom: 16}}>{feature.icon}</div>
                <h3 style={{fontSize: 20, fontWeight: 600, marginBottom: 12, color: '#ffffff'}}>{feature.title}</h3>
                <p style={{color: 'rgba(255,255,255,0.85)', lineHeight: 1.6}}>{feature.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="about" style={{
        background: 'rgba(0,0,0,0.1)',
        padding: '96px 32px',
        borderTop: '1px solid rgba(255,255,255,0.2)',
        borderBottom: '1px solid rgba(255,255,255,0.2)'
      }}>
        <div style={{maxWidth: 1280, margin: '0 auto'}}>
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 64,
            alignItems: 'center'
          }}>
            <div>
              <h2 style={{fontSize: 40, fontWeight: 600, marginBottom: 24}}>
                Zdrowie psychiczne to priorytet
              </h2>
              <p style={{color: 'rgba(255,255,255,0.9)', fontSize: 18, lineHeight: 1.7, marginBottom: 16}}>
                W dzisiejszym szybkim świecie łatwo jest stracić kontakt ze sobą. HelpForMind został 
                stworzony, aby pomóc Ci zauważyć wzorce, zrozumieć emocje i dbać o zdrowie psychiczne.
              </p>
              <p style={{color: 'rgba(255,255,255,0.9)', fontSize: 18, lineHeight: 1.7, marginBottom: 32}}>
                Nasze narzędzia oparte na sztucznej inteligencji i sprawdzonej psychologii 
                pomagają codziennie wielu osobom na całym świecie.
              </p>
              <button 
                onClick={() => router.push('/login')}
                style={{
                  padding: '16px 32px',
                  background: 'rgba(255,255,255,0.95)',
                  border: 'none',
                  borderRadius: 12,
                  color: '#667eea',
                  fontSize: 16,
                  fontWeight: 700,
                  cursor: 'pointer',
                  boxShadow: '0 4px 16px rgba(0,0,0,0.2)',
                  transition: 'all 0.3s'
                }}
              >
                Dowiedz się więcej
              </button>
            </div>
            <div style={{
              background: 'rgba(255,255,255,0.2)',
              borderRadius: 16,
              height: 400,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 120,
              border: '2px solid rgba(255,255,255,0.3)',
              backdropFilter: 'blur(10px)',
              boxShadow: '0 8px 32px rgba(0,0,0,0.2)'
            }}>
              🧠
            </div>
          </div>
        </div>
      </section>

      <section style={{
        background: 'rgba(255,255,255,0.15)',
        padding: '96px 32px',
        textAlign: 'center',
        backdropFilter: 'blur(10px)',
        borderTop: '1px solid rgba(255,255,255,0.2)',
        borderBottom: '1px solid rgba(255,255,255,0.2)'
      }}>
        <div style={{maxWidth: 800, margin: '0 auto'}}>
          <h2 style={{fontSize: 48, fontWeight: 600, marginBottom: 24}}>
            Zacznij dbać o siebie już dziś
          </h2>
          <p style={{fontSize: 20, marginBottom: 40, color: 'rgba(255,255,255,0.95)'}}>
            Dołącz do wielu użytkowników, którzy poprawili swoje zdrowie psychiczne z HelpForMind.
          </p>
          <button 
            onClick={() => router.push('/login')}
            style={{
              padding: '18px 56px',
              background: '#ffffff',
              border: 'none',
              borderRadius: 12,
              color: '#667eea',
              fontSize: 20,
              fontWeight: 700,
              cursor: 'pointer',
              boxShadow: '0 10px 40px rgba(0,0,0,0.4)',
              transition: 'all 0.3s'
            }}
          >
            Załóż darmowe konto
          </button>
        </div>
      </section>

      <footer style={{
        borderTop: '1px solid rgba(255,255,255,0.2)',
        padding: '48px 32px',
        textAlign: 'center',
        background: 'rgba(0,0,0,0.2)'
      }}>
        <div style={{maxWidth: 1280, margin: '0 auto'}}>
          <div style={{marginBottom: 24}}>
            <span style={{fontSize: 32, marginRight: 12}}>🧠</span>
            <span style={{fontSize: 20, fontWeight: 600}}>HelpForMind</span>
          </div>
          <p style={{color: 'rgba(255,255,255,0.7)', fontSize: 14}}>
            © 2025 HelpForMind. Wszystkie prawa zastrzeżone.
            <br></br>
            Milan Wieliczko, Franciszek Chyliński 
          </p>
        </div>
      </footer>
    </div>
  );
}
