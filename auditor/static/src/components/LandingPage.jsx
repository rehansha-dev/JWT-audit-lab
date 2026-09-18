import { useRef, useEffect } from 'react';

const CELL = 52;
const BORDER = 'rgba(255,255,255,0.07)';
const HOVER_COLOR = 'rgba(242,168,168,0.35)';
const TRAIL_DECAY = 0.88;

export default function LandingPage({ onStart }) {
  const canvasRef = useRef(null);
  const mouse = useRef({ x: -999, y: -999 });
  const cells = useRef(new Map());
  const raf = useRef(null);
  const offset = useRef({ x: 0, y: 0 });

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    // NOTE: matches the draw loop's realCol/realRow formula (uses `+ CELL`) so the
    // cell that lights up is exactly the one under the cursor.
    const getCell = (mx, my) => {
      const col = Math.floor((mx - offset.current.x + CELL) / CELL);
      const row = Math.floor((my - offset.current.y + CELL) / CELL);
      return `${col},${row}`;
    };

    const onMouseMove = (e) => {
      mouse.current = { x: e.clientX, y: e.clientY };
      const key = getCell(e.clientX, e.clientY);
      cells.current.set(key, 1.0);
    };

    const onMouseLeave = () => {
      mouse.current = { x: -999, y: -999 };
    };

    canvas.addEventListener('mousemove', onMouseMove);
    canvas.addEventListener('mouseleave', onMouseLeave);

    const draw = () => {
      const W = canvas.width;
      const H = canvas.height;

      offset.current.x = (offset.current.x - 0.2 + CELL) % CELL;
      offset.current.y = (offset.current.y - 0.15 + CELL) % CELL;

      ctx.clearRect(0, 0, W, H);

      const startX = offset.current.x - CELL;
      const startY = offset.current.y - CELL;
      const cols = Math.ceil(W / CELL) + 2;
      const rows = Math.ceil(H / CELL) + 2;

      for (let c = 0; c < cols; c++) {
        for (let r = 0; r < rows; r++) {
          const sx = c * CELL + startX;
          const sy = r * CELL + startY;

          const realCol = Math.floor((sx - offset.current.x + CELL) / CELL);
          const realRow = Math.floor((sy - offset.current.y + CELL) / CELL);
          const key = `${realCol},${realRow}`;

          const alpha = cells.current.get(key) || 0;

          if (alpha > 0.01) {
            ctx.fillStyle = `rgba(242,168,168,${alpha * 0.3})`;
            ctx.fillRect(sx, sy, CELL, CELL);

            ctx.strokeStyle = `rgba(242,168,168,${alpha * 0.8})`;
            ctx.lineWidth = 0.8;
            ctx.strokeRect(sx + 0.5, sy + 0.5, CELL - 1, CELL - 1);

            cells.current.set(key, alpha * TRAIL_DECAY);
            if (alpha * TRAIL_DECAY < 0.01) cells.current.delete(key);
          } else {
            ctx.strokeStyle = BORDER;
            ctx.lineWidth = 0.5;
            ctx.strokeRect(sx + 0.5, sy + 0.5, CELL - 1, CELL - 1);
          }
        }
      }

      raf.current = requestAnimationFrame(draw);
    };

    raf.current = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf.current);
      window.removeEventListener('resize', resize);
      canvas.removeEventListener('mousemove', onMouseMove);
      canvas.removeEventListener('mouseleave', onMouseLeave);
    };
  }, []);

  return (
    <div style={{
      position: 'relative',
      width: '100vw',
      height: '100vh',
      overflow: 'hidden',
      background: '#080810',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
    }}>

      {/* Canvas fills entire background */}
      <canvas
        ref={canvasRef}
        style={{
          position: 'absolute',
          inset: 0,
          width: '100%',
          height: '100%',
          display: 'block',
        }}
      />

      {/* Radial fade from center so content is readable */}
      <div style={{
        position: 'absolute',
        inset: 0,
        background: 'radial-gradient(ellipse 55% 55% at 50% 50%, rgba(8,8,16,0.7) 0%, transparent 100%)',
        pointerEvents: 'none',
      }} />

      {/* Edge vignette */}
      <div style={{
        position: 'absolute',
        inset: 0,
        background: 'radial-gradient(ellipse 100% 100% at 50% 50%, transparent 50%, rgba(8,8,16,0.95) 100%)',
        pointerEvents: 'none',
      }} />

      {/* Center content */}
      <div style={{
        position: 'relative',
        zIndex: 10,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 0,
        textAlign: 'center',
        padding: '0 24px',
        userSelect: 'none',
      }}>

        {/* Badge */}
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 8,
          background: 'rgba(242,168,168,0.08)',
          border: '1px solid rgba(242,168,168,0.25)',
          borderRadius: 9999,
          padding: '7px 20px',
          marginBottom: 32,
          animation: 'fadeUp 0.6s ease-out 0.1s both',
        }}>
          <div style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: '#f2a8a8',
            boxShadow: '0 0 6px rgba(242,168,168,0.8)',
          }} />
          <span style={{
            fontFamily: 'Inter, sans-serif',
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: '2px',
            textTransform: 'uppercase',
            color: '#f2a8a8',
          }}>
            Authorized Security Research Tool
          </span>
        </div>

        {/* Headline */}
        <div style={{
          marginBottom: 20,
          animation: 'fadeUp 0.6s ease-out 0.2s both',
        }}>
          <span style={{
            fontFamily: 'Sora, sans-serif',
            fontSize: 'clamp(52px, 9vw, 92px)',
            fontWeight: 800,
            letterSpacing: '-3px',
            lineHeight: 0.92,
            color: '#eeeef2',
            display: 'block',
          }}>
            JWT Audit{' '}
            <span style={{
              background: 'linear-gradient(135deg, #f2a8a8 0%, #e07070 50%, #f2a8a8 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
              filter: 'drop-shadow(0 0 30px rgba(242,168,168,0.4))',
            }}>
              Lab
            </span>
          </span>
        </div>

        {/* Subtitle */}
        <p style={{
          fontFamily: 'Inter, sans-serif',
          fontSize: 18,
          fontWeight: 300,
          color: '#8888a0',
          maxWidth: 460,
          lineHeight: 1.6,
          marginBottom: 40,
          animation: 'fadeUp 0.6s ease-out 0.3s both',
        }}>
          Black-box JWT vulnerability detection
          with zero false positives
        </p>

        {/* Stats row */}
        <div style={{
          display: 'flex',
          gap: 10,
          marginBottom: 48,
          flexWrap: 'wrap',
          justifyContent: 'center',
          animation: 'fadeUp 0.6s ease-out 0.4s both',
        }}>
          {[
            { label: '7 Attack Probes', color: '#f2a8a8' },
            { label: '2 CVEs Covered', color: '#c4a8f4' },
            { label: 'Zero False Positives', color: '#93d4a8' },
          ].map(({ label, color }) => (
            <div key={label} style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: 9999,
              padding: '9px 20px',
            }}>
              <div style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: color,
                boxShadow: `0 0 6px ${color}`,
              }} />
              <span style={{
                fontFamily: 'Inter, sans-serif',
                fontSize: 13,
                fontWeight: 500,
                color: '#9090a8',
              }}>{label}</span>
            </div>
          ))}
        </div>

        {/* CTA Button */}
        <button
          onClick={onStart}
          style={{
            position: 'relative',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 10,
            background: 'linear-gradient(135deg, #f2a8a8 0%, #e07878 100%)',
            color: '#1a0808',
            fontFamily: 'Sora, sans-serif',
            fontSize: 16,
            fontWeight: 700,
            padding: '17px 52px',
            borderRadius: 13,
            border: 'none',
            cursor: 'pointer',
            marginBottom: 20,
            boxShadow: '0 0 0 1px rgba(255,255,255,0.15) inset, 0 8px 40px rgba(242,168,168,0.4)',
            transition: 'transform 0.15s ease, box-shadow 0.15s ease',
            animation: 'fadeUp 0.6s ease-out 0.5s both',
          }}
          onMouseEnter={e => {
            e.currentTarget.style.transform = 'translateY(-3px)';
            e.currentTarget.style.boxShadow = '0 0 0 1px rgba(255,255,255,0.15) inset, 0 16px 50px rgba(242,168,168,0.55)';
          }}
          onMouseLeave={e => {
            e.currentTarget.style.transform = 'translateY(0)';
            e.currentTarget.style.boxShadow = '0 0 0 1px rgba(255,255,255,0.15) inset, 0 8px 40px rgba(242,168,168,0.4)';
          }}
        >
          Start Audit
          <span style={{ fontSize: 18 }}>→</span>
        </button>

        {/* Helper */}
        <p style={{
          fontFamily: 'Inter, sans-serif',
          fontSize: 12,
          color: '#3a3a50',
          animation: 'fadeUp 0.6s ease-out 0.6s both',
        }}>
          Runs against localhost:4000 by default
        </p>
      </div>

      <style>{`
        @keyframes fadeUp {
          from { opacity: 0; transform: translateY(14px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
