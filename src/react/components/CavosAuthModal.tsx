'use client';

import React, {
  useState,
  useEffect,
  useCallback,
  useRef,
  type CSSProperties,
} from 'react';
import { useCavos } from '../CavosContext';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CavosAuthModalProps {
  open: boolean;
  onClose: () => void;
  onSuccess?: (address: string) => void;
  appName?: string;
  appLogo?: string;
  providers?: ('google' | 'apple' | 'email')[];
  primaryColor?: string;
}

type Screen = 'select' | 'email-password' | 'verify' | 'deploying';
type EmailMode = 'login' | 'register';


// ─── Style injection ──────────────────────────────────────────────────────────

const STYLE_ID = 'cavos-modal-styles-v2';

function injectStyles() {
  if (typeof document === 'undefined') return;
  if (document.getElementById(STYLE_ID)) return;
  const el = document.createElement('style');
  el.id = STYLE_ID;
  el.textContent = `
    @keyframes cavos-fade { from { opacity:0; } to { opacity:1; } }
    @keyframes cavos-up {
      from { opacity:0; transform:translateY(12px) scale(0.985); }
      to   { opacity:1; transform:translateY(0)    scale(1);     }
    }
    @keyframes cavos-spin {
      from { transform:rotate(0deg); } to { transform:rotate(360deg); }
    }
    @keyframes cavos-pop {
      0%   { transform:scale(0.5);  opacity:0; }
      60%  { transform:scale(1.12); opacity:1; }
      100% { transform:scale(1);    opacity:1; }
    }
    @keyframes cavos-check-draw {
      from { stroke-dashoffset: 30; }
      to   { stroke-dashoffset: 0;  }
    }
    @keyframes cavos-ring-glow {
      0%,100% { box-shadow: 0 0 0 0 rgba(34,197,94,0.4); }
      50%      { box-shadow: 0 0 0 10px rgba(34,197,94,0); }
    }
    .cavos-check-circle {
      animation: cavos-pop 0.45s cubic-bezier(.22,1,.36,1) forwards;
    }
    .cavos-check-path {
      stroke-dasharray: 30;
      stroke-dashoffset: 30;
      animation: cavos-check-draw 0.35s 0.2s cubic-bezier(.22,1,.36,1) forwards;
    }
    .cavos-input-row:focus-within {
      border-color: rgba(0,0,0,0.35) !important;
      box-shadow: 0 0 0 3px rgba(0,0,0,0.06) !important;
    }
    .cavos-input-inner:focus { outline:none; }
    .cavos-provider:hover { background:#f7f7f7 !important; }
    .cavos-provider:active { transform:scale(0.99); }
    .cavos-close:hover { background:rgba(0,0,0,0.05) !important; }
    .cavos-sub-btn:hover { color:rgba(0,0,0,0.6) !important; }
    .cavos-submit-btn:hover { color:rgba(0,0,0,0.8) !important; }
    .cavos-primary-btn:hover { opacity:0.88; }
    .cavos-primary-btn:active { transform:scale(0.98); }
  `;
  document.head.appendChild(el);
}

// ─── Icons ────────────────────────────────────────────────────────────────────

const GoogleIcon = () => (
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
    <path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.875 2.684-6.615z" fill="#4285F4"/>
    <path d="M9 18c2.43 0 4.467-.806 5.956-2.184l-2.908-2.258c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 009 18z" fill="#34A853"/>
    <path d="M3.964 10.707A5.41 5.41 0 013.682 9c0-.593.102-1.17.282-1.707V4.961H.957A8.996 8.996 0 000 9c0 1.452.348 2.827.957 4.039l3.007-2.332z" fill="#FBBC05"/>
    <path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 00.957 4.961L3.964 7.293C4.672 5.163 6.656 3.58 9 3.58z" fill="#EA4335"/>
  </svg>
);

const AppleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 814 1000" fill="currentColor">
    <path d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76 0-103.7 40.8-165.9 40.8s-105-57.8-155.5-127.4C46 790.7 0 663 0 541.8c0-194.3 126.4-297.5 250.8-297.5 66.1 0 121.2 43.4 162.7 43.4 39.5 0 101.1-46 176.3-46 28.5 0 130.9 2.6 198.3 99.2zm-234-181.5c31.1-36.9 53.1-88.1 53.1-139.3 0-7.1-.6-14.3-1.9-20.1-50.6 1.9-110.8 33.7-147.1 75.8-28.5 32.4-55.1 83.6-55.1 135.5 0 7.8 1.3 15.6 1.9 18.1 3.2.6 8.4 1.3 13.6 1.3 45.4 0 102.5-30.4 135.5-71.3z"/>
  </svg>
);

const EmailIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="4" width="20" height="16" rx="2"/>
    <path d="m22 7-8.97 5.7a1.94 1.94 0 01-2.06 0L2 7"/>
  </svg>
);

const CavosLogo = () => (
  <svg width="12" height="12" viewBox="0 0 32 32" fill="currentColor">
    <circle cx="16" cy="16" r="16" fillOpacity="0.2"/>
    <circle cx="16" cy="16" r="8"/>
  </svg>
);

function Spinner({ size = 16, color = '#888' }: { size?: number; color?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      style={{ animation: 'cavos-spin 0.75s linear infinite', flexShrink: 0 }}>
      <circle cx="12" cy="12" r="10" stroke={color} strokeOpacity="0.2" strokeWidth="2.5"/>
      <path d="M12 2a10 10 0 0110 10" stroke={color} strokeWidth="2.5" strokeLinecap="round"/>
    </svg>
  );
}

// ─── Shared layout shells ─────────────────────────────────────────────────────

const base: CSSProperties = {
  position: 'fixed', inset: 0,
  background: 'rgba(0,0,0,0.5)',
  backdropFilter: 'blur(10px)',
  WebkitBackdropFilter: 'blur(10px)',
  zIndex: 9999,
  display: 'flex', alignItems: 'center', justifyContent: 'center',
  padding: '16px',
  animation: 'cavos-fade 0.18s ease',
  fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif',
};

const whiteCard: CSSProperties = {
  background: '#ffffff',
  borderRadius: '22px',
  width: '100%',
  maxWidth: '400px',
  boxShadow: '0 24px 60px rgba(0,0,0,0.22), 0 0 0 1px rgba(0,0,0,0.05)',
  animation: 'cavos-up 0.25s cubic-bezier(0.22,1,0.36,1)',
  overflow: 'hidden',
};

const darkCard: CSSProperties = {
  background: '#0d0d0d',
  borderRadius: '22px',
  width: '100%',
  maxWidth: '400px',
  boxShadow: '0 24px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.07)',
  animation: 'cavos-up 0.25s cubic-bezier(0.22,1,0.36,1)',
  overflow: 'hidden',
};

const providerBtn: CSSProperties = {
  width: '100%',
  display: 'flex', alignItems: 'center', gap: '12px',
  padding: '13px 16px',
  background: '#fff',
  border: '1px solid rgba(0,0,0,0.1)',
  borderRadius: '12px',
  cursor: 'pointer',
  fontSize: '14px',
  fontWeight: 500,
  color: '#111',
  textAlign: 'left',
  fontFamily: 'inherit',
  transition: 'background 0.15s, transform 0.1s',
};

const footerBar: CSSProperties = {
  borderTop: '1px solid rgba(0,0,0,0.06)',
  padding: '12px 20px',
  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '5px',
  fontSize: '11px', color: 'rgba(0,0,0,0.28)',
};

const closeBtn: CSSProperties = {
  position: 'absolute', top: '16px', right: '16px',
  width: '28px', height: '28px', borderRadius: '50%',
  border: 'none', background: 'transparent',
  cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
  color: 'rgba(0,0,0,0.3)', padding: 0, transition: 'background 0.15s',
};

const CloseX = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
  </svg>
);

// ─── Main component ───────────────────────────────────────────────────────────

export function CavosAuthModal({
  open,
  onClose,
  onSuccess,
  appName,
  providers = ['google', 'apple', 'email'],
  primaryColor = '#0A0908',
}: CavosAuthModalProps) {
  const { cavos, login, register, isAuthenticated, address, isLoading } = useCavos();

  const [screen, setScreen] = useState<Screen>('select');
  const [emailMode, setEmailMode] = useState<EmailMode>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [deployState, setDeployState] = useState<'loading' | 'done'>('loading');

  const doneHandledRef = useRef(false);
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const closeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const onSuccessRef = useRef(onSuccess);
  const onCloseRef = useRef(onClose);
  useEffect(() => { onSuccessRef.current = onSuccess; }, [onSuccess]);
  useEffect(() => { onCloseRef.current = onClose; }, [onClose]);

  useEffect(() => { injectStyles(); }, []);

  const triggerDone = useCallback((addr: string) => {
    if (doneHandledRef.current) return;
    doneHandledRef.current = true;

    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);

    setScreen('deploying');
    setDeployState('done');

    closeTimerRef.current = setTimeout(() => {
      onSuccessRef.current?.(addr);
      onCloseRef.current();
      setScreen('select');
      setDeployState('loading');
      setEmail(''); setPassword(''); setError('');
      doneHandledRef.current = false;
    }, 1600);
  }, []);

  // Enter deploying screen as soon as authenticated, then start polling
  useEffect(() => {
    if (!open || !isAuthenticated || !address) return;

    // Go to deploying screen
    if (screen !== 'deploying' && screen !== 'verify') {
      setScreen('deploying');
      setDeployState('loading');
      doneHandledRef.current = false;
    }

    // 1. Check current SDK status immediately
    const currentStatus = cavos.getWalletStatus();
    if (currentStatus.isReady) {
      triggerDone(address);
      return;
    }

    // 2. Subscribe to SDK status changes
    const unsub = cavos.onWalletStatusChange((status) => {
      if (status.isReady && address) triggerDone(address);
    });

    // 3. Poll isAccountDeployed every 3s as fallback
    //    (handles case where SDK emits isReady:true but React misses the event)
    pollIntervalRef.current = setInterval(async () => {
      const status = cavos.getWalletStatus();
      if (status.isReady && address) {
        triggerDone(address);
        return;
      }
      // Hard fallback: if deployed + not deploying/registering for >0 checks, close anyway
      // so the user isn't stuck forever (wallet is usable via JWT path)
      try {
        const deployed = await cavos.isAccountDeployed();
        const fresh = cavos.getWalletStatus();
        if (deployed && !fresh.isDeploying && !fresh.isRegistering && address) {
          // Wallet deployed and no active operation — usable even without session registration
          triggerDone(address);
        }
      } catch { /* ignore poll errors */ }
    }, 3000);

    return () => {
      unsub();
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, isAuthenticated, address]);

  useEffect(() => () => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    if (closeTimerRef.current) clearTimeout(closeTimerRef.current);
  }, []);

  const handleClose = () => {
    if (screen === 'deploying') return;
    setScreen('select'); setError('');
    doneHandledRef.current = false;
    onCloseRef.current();
  };

  const handleOAuth = async (provider: 'google' | 'apple') => {
    setError(''); setBusy(true);
    try {
      await login(provider);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Authentication failed.';
      setError(msg); setBusy(false);
    }
  };

  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;
    setError(''); setBusy(true);
    try {
      if (emailMode === 'login') {
        await login('firebase', { email, password });
      } else {
        await register('firebase', { email, password });
        setScreen('verify'); setBusy(false); return;
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : '';
      if (msg.toLowerCase().includes('verif')) {
        setScreen('verify');
      } else {
        setError(msg || 'Authentication failed.');
      }
      setBusy(false);
    }
  };

  if (!open) return null;

  // ── Deploying ──────────────────────────────────────────────────────────────

  if (screen === 'deploying') {
    const isDone = deployState === 'done';
    return (
      <div style={base} role="dialog" aria-modal>
        <div style={darkCard}>
          <div style={{
            padding: '52px 28px 44px',
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            textAlign: 'center', gap: '16px',
          }}>
            {/* Icon: spinner or checkmark */}
            {isDone ? (
              <div
                className="cavos-check-circle"
                style={{
                  width: 64, height: 64, borderRadius: '50%',
                  background: 'rgba(34,197,94,0.12)',
                  border: '1.5px solid rgba(34,197,94,0.35)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  animation: 'cavos-ring-glow 1.5s ease-out',
                }}
              >
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
                  <polyline
                    className="cavos-check-path"
                    points="20 6 9 17 4 12"
                    stroke="#22c55e"
                    strokeWidth="2.2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>
            ) : (
              <div style={{
                width: 64, height: 64, borderRadius: '50%',
                background: 'rgba(255,255,255,0.04)',
                border: '1.5px solid rgba(255,255,255,0.08)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Spinner size={26} color="rgba(255,255,255,0.6)" />
              </div>
            )}

            {/* Text */}
            <div>
              <h2 style={{
                margin: 0, fontSize: '17px', fontWeight: 600,
                color: '#fff', letterSpacing: '-0.02em',
                transition: 'opacity 0.3s',
              }}>
                {isDone ? "You're all set" : 'Setting up your account'}
              </h2>
              <p style={{
                margin: '6px 0 0', fontSize: '13px',
                color: 'rgba(255,255,255,0.35)',
              }}>
                {isDone ? 'Your wallet is ready' : 'This only takes a moment…'}
              </p>
            </div>
          </div>

          <div style={{ ...footerBar, borderTop: '1px solid rgba(255,255,255,0.05)', color: 'rgba(255,255,255,0.18)' }}>
            <CavosLogo /><span>Secured by Cavos</span>
          </div>
        </div>
      </div>
    );
  }

  // ── Verify email ───────────────────────────────────────────────────────────

  if (screen === 'verify') {
    return (
      <div style={base} role="dialog" aria-modal onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
        <div style={{ ...whiteCard, position: 'relative' }}>
          <button className="cavos-close" style={closeBtn} onClick={handleClose} aria-label="Close">
            <CloseX />
          </button>
          <div style={{ padding: '40px 24px 24px', textAlign: 'center' }}>
            <div style={{
              width: 48, height: 48, borderRadius: '50%', margin: '0 auto 16px',
              background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.18)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
              </svg>
            </div>
            <h2 style={{ margin: '0 0 8px', fontSize: '17px', fontWeight: 600, color: '#111', letterSpacing: '-0.02em' }}>
              Check your inbox
            </h2>
            <p style={{ margin: '0 0 22px', fontSize: '13px', color: 'rgba(0,0,0,0.45)', lineHeight: 1.55 }}>
              We sent a link to <strong style={{ color: '#111', fontWeight: 500 }}>{email}</strong>.<br/>Click it to verify your account.
            </p>
            <button
              className="cavos-primary-btn"
              style={{
                width: '100%', padding: '12px', borderRadius: '12px', border: 'none',
                background: primaryColor, color: '#fff', fontSize: '14px', fontWeight: 500,
                cursor: 'pointer', fontFamily: 'inherit', transition: 'opacity 0.15s, transform 0.1s',
                marginBottom: '8px',
              }}
              onClick={() => { setScreen('email-password'); setError(''); }}
            >
              Back to sign in
            </button>
          </div>
          <div style={footerBar}><CavosLogo /><span>Secured by Cavos</span></div>
        </div>
      </div>
    );
  }

  // ── Email + password form ──────────────────────────────────────────────────

  if (screen === 'email-password') {
    return (
      <div style={base} role="dialog" aria-modal onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
        <div style={{ ...whiteCard, position: 'relative' }}>
          {/* Back button */}
          <button
            className="cavos-close"
            style={{ ...closeBtn, left: '16px', right: 'auto' }}
            onClick={() => { setScreen('select'); setError(''); }}
            aria-label="Back"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M19 12H5M12 5l-7 7 7 7"/>
            </svg>
          </button>
          <button className="cavos-close" style={closeBtn} onClick={handleClose} aria-label="Close">
            <CloseX />
          </button>

          <div style={{ padding: '52px 22px 22px' }}>
            <h2 style={{
              margin: '0 0 20px', fontSize: '17px', fontWeight: 600,
              color: '#111', letterSpacing: '-0.02em', textAlign: 'center',
            }}>
              {emailMode === 'login' ? 'Sign in with email' : 'Create your account'}
            </h2>

            {error && (
              <div style={{
                background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.18)',
                borderRadius: '10px', padding: '10px 14px',
                fontSize: '13px', color: '#dc2626', marginBottom: '14px',
              }}>
                {error}
              </div>
            )}

            <form onSubmit={handleEmailSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <input
                className="cavos-input-inner"
                style={{
                  width: '100%', padding: '12px 14px',
                  border: '1px solid rgba(0,0,0,0.12)', borderRadius: '12px',
                  fontSize: '14px', color: '#111', background: '#fff',
                  fontFamily: 'inherit', boxSizing: 'border-box',
                  transition: 'border-color 0.15s',
                }}
                type="email"
                placeholder="your@email.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                disabled={busy}
                autoFocus
              />
              <input
                className="cavos-input-inner"
                style={{
                  width: '100%', padding: '12px 14px',
                  border: '1px solid rgba(0,0,0,0.12)', borderRadius: '12px',
                  fontSize: '14px', color: '#111', background: '#fff',
                  fontFamily: 'inherit', boxSizing: 'border-box',
                  transition: 'border-color 0.15s',
                }}
                type="password"
                placeholder="Password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                disabled={busy}
                minLength={emailMode === 'register' ? 8 : undefined}
              />

              <button
                type="submit"
                className="cavos-primary-btn"
                style={{
                  width: '100%', padding: '12px', marginTop: '4px',
                  borderRadius: '12px', border: 'none',
                  background: primaryColor, color: '#fff',
                  fontSize: '14px', fontWeight: 500,
                  cursor: 'pointer', fontFamily: 'inherit',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
                  transition: 'opacity 0.15s, transform 0.1s',
                  opacity: busy ? 0.65 : 1,
                }}
                disabled={busy || isLoading}
              >
                {busy && <Spinner size={15} color="#fff" />}
                {busy ? 'Continuing…' : emailMode === 'login' ? 'Sign in' : 'Create account'}
              </button>
            </form>

            <button
              className="cavos-sub-btn"
              style={{
                background: 'none', border: 'none', cursor: 'pointer',
                fontSize: '13px', color: 'rgba(0,0,0,0.38)',
                width: '100%', textAlign: 'center', padding: '12px 0 0',
                fontFamily: 'inherit', transition: 'color 0.15s',
              }}
              onClick={() => { setEmailMode(m => m === 'login' ? 'register' : 'login'); setError(''); }}
            >
              {emailMode === 'login'
                ? <>No account? <strong style={{ color: '#111', fontWeight: 500 }}>Sign up</strong></>
                : <>Have an account? <strong style={{ color: '#111', fontWeight: 500 }}>Sign in</strong></>
              }
            </button>
          </div>

          <div style={footerBar}><CavosLogo /><span>Secured by Cavos</span></div>
        </div>
      </div>
    );
  }

  // ── Provider selection (main screen) ───────────────────────────────────────

  const showEmail = providers.includes('email');
  const showGoogle = providers.includes('google');
  const showApple = providers.includes('apple');

  return (
    <div style={base} role="dialog" aria-modal onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ ...whiteCard, position: 'relative' }}>
        <button className="cavos-close" style={closeBtn} onClick={handleClose} aria-label="Close">
          <CloseX />
        </button>

        <div style={{ padding: '40px 22px 22px' }}>
          {/* Title */}
          <h2 style={{
            margin: '0 0 22px', fontSize: '17px', fontWeight: 600,
            color: '#111', letterSpacing: '-0.02em', textAlign: 'center',
          }}>
            {appName ? `Sign in to ${appName}` : 'Log in or sign up'}
          </h2>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>

            {/* Email inline input row — shown first like Privy */}
            {showEmail && (
              <div
                className="cavos-input-row"
                style={{
                  display: 'flex', alignItems: 'center',
                  border: '1px solid rgba(0,0,0,0.1)', borderRadius: '12px',
                  overflow: 'hidden', background: '#fff',
                  transition: 'border-color 0.15s, box-shadow 0.15s',
                }}
              >
                <div style={{ padding: '0 12px', color: 'rgba(0,0,0,0.3)', display: 'flex', alignItems: 'center', flexShrink: 0 }}>
                  <EmailIcon />
                </div>
                <input
                  className="cavos-input-inner"
                  style={{
                    flex: 1, padding: '13px 0', border: 'none', background: 'transparent',
                    fontSize: '14px', color: '#111', fontFamily: 'inherit',
                  }}
                  type="email"
                  placeholder="your@email.com"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' && email) {
                      setScreen('email-password');
                    }
                  }}
                  disabled={busy || isLoading}
                />
                {email && (
                  <button
                    className="cavos-submit-btn"
                    style={{
                      padding: '0 16px', height: '100%', border: 'none', background: 'transparent',
                      fontSize: '13px', fontWeight: 500, color: 'rgba(0,0,0,0.4)',
                      cursor: 'pointer', fontFamily: 'inherit', transition: 'color 0.15s',
                      flexShrink: 0,
                    }}
                    onClick={() => setScreen('email-password')}
                  >
                    Submit
                  </button>
                )}
              </div>
            )}

            {/* Google */}
            {showGoogle && (
              <button
                className="cavos-provider"
                style={{ ...providerBtn, ...(busy || isLoading ? { opacity: 0.5, cursor: 'not-allowed' } : {}) }}
                onClick={() => handleOAuth('google')}
                disabled={busy || isLoading}
              >
                <div style={{ width: 32, height: 32, borderRadius: '8px', background: '#fff', border: '1px solid rgba(0,0,0,0.08)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  {busy ? <Spinner size={16} color="#888" /> : <GoogleIcon />}
                </div>
                <span>Google</span>
              </button>
            )}

            {/* Apple */}
            {showApple && (
              <button
                className="cavos-provider"
                style={{ ...providerBtn, ...(busy || isLoading ? { opacity: 0.5, cursor: 'not-allowed' } : {}) }}
                onClick={() => handleOAuth('apple')}
                disabled={busy || isLoading}
              >
                <div style={{ width: 32, height: 32, borderRadius: '8px', background: '#0A0908', border: '1px solid #0A0908', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, color: '#fff' }}>
                  {busy ? <Spinner size={16} color="#fff" /> : <AppleIcon />}
                </div>
                <span>Apple</span>
              </button>
            )}
          </div>

          {error && (
            <div style={{
              marginTop: '14px', background: 'rgba(239,68,68,0.06)',
              border: '1px solid rgba(239,68,68,0.18)', borderRadius: '10px',
              padding: '9px 13px', fontSize: '13px', color: '#dc2626',
            }}>
              {error}
            </div>
          )}

          {/* Legal */}
          <p style={{
            margin: '16px 0 0', fontSize: '11px',
            color: 'rgba(0,0,0,0.28)', textAlign: 'center', lineHeight: 1.55,
          }}>
            By continuing you agree to the{' '}
            <a href="https://cavos.xyz/privacy" target="_blank" rel="noopener noreferrer"
              style={{ color: 'rgba(0,0,0,0.45)', textDecoration: 'underline' }}>
              Privacy Policy
            </a>
            {' & '}
            <a href="https://cavos.xyz/dpa" target="_blank" rel="noopener noreferrer"
              style={{ color: 'rgba(0,0,0,0.45)', textDecoration: 'underline' }}>
              Terms
            </a>.
          </p>
        </div>

        <div style={footerBar}><CavosLogo /><span>Secured by Cavos</span></div>
      </div>
    </div>
  );
}

// ─── useCavosAuth hook ────────────────────────────────────────────────────────

export function useCavosAuth() {
  const { openModal, closeModal, isAuthenticated, address, user, walletStatus, logout } = useCavos();
  return { openModal, closeModal, isAuthenticated, address, user, walletStatus, logout };
}
